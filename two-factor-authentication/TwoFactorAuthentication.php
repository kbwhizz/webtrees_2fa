<?php

declare(strict_types=1);

namespace TwoFactorAuthentication;

use Aura\Router\Route;
use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use Fisharebest\Webtrees\Auth;
use Fisharebest\Webtrees\FlashMessages;
use Fisharebest\Webtrees\Http\RequestHandlers\LoginAction;
use Fisharebest\Webtrees\Http\RequestHandlers\LoginPage;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Module\AbstractModule;
use Fisharebest\Webtrees\Module\ModuleCustomInterface;
use Fisharebest\Webtrees\Module\ModuleCustomTrait;
use Fisharebest\Webtrees\Module\ModuleGlobalInterface;
use Fisharebest\Webtrees\Module\ModuleGlobalTrait;
use Fisharebest\Webtrees\Module\ModuleMenuInterface;
use Fisharebest\Webtrees\Module\ModuleMenuTrait;
use Fisharebest\Webtrees\Menu;
use Fisharebest\Webtrees\Registry;
use Fisharebest\Webtrees\Services\UserService;
use Fisharebest\Webtrees\Session;
use Fisharebest\Webtrees\Tree;
use Fisharebest\Webtrees\View;
use PragmaRX\Google2FA\Google2FA;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Fisharebest\Webtrees\Services\TreeService;
use Fisharebest\Webtrees\Site;
use Fisharebest\Webtrees\Contracts\UserInterface;

/**
 * Optional Google Authenticator (TOTP) two-factor login for webtrees 2.2.
 *
 * - Users enable/disable 2FA on their own settings page (see the menu link).
 * - The secret and flags are stored as normal user preferences (no schema changes).
 * - The login POST is checked in middleware: if the password is right and the user has
 *   2FA enabled, a valid code must also be supplied.
 */
class TwoFactorAuthentication extends AbstractModule implements
    ModuleCustomInterface,
    ModuleGlobalInterface,
    ModuleMenuInterface,
    MiddlewareInterface
{
    use ModuleCustomTrait;
    use ModuleGlobalTrait;
    use ModuleMenuTrait;

    private const PREF_ENABLED = 'two_factor_enabled';
    private const PREF_SECRET  = 'two_factor_secret';
    private const PREF_LAST    = 'two_factor_last_timestamp';
    private const SESSION_KEY  = 'two_factor_pending_secret';
    private const PREF_FAILURES     = 'two_factor_failures';
    private const PREF_LOCKED_UNTIL = 'two_factor_locked_until';
    private const MAX_FAILURES      = 5;   // wrong codes allowed before locking
    private const LOCK_SECONDS      = 300; // length of the lock    

    public function title(): string
    {
        return I18N::translate('Google two-factor authentication');
    }

    public function description(): string
    {
        return I18N::translate('Allows users to optionally enable Google Authenticator two-factor login.');
    }

    public function customModuleAuthorName(): string
    {
        return 'Bernard Scaife';
    }

    public function customModuleVersion(): string
    {
        return '1.0.0';
    }

    public function customModuleLatestVersionUrl(): string
    {
        return '';
    }

    public function customModuleSupportUrl(): string
    {
        return '';
    }

    public function resourcesFolder(): string
    {
        return __DIR__ . '/resources/';
    }

    public function boot(): void
    {
        View::registerNamespace($this->name(), $this->resourcesFolder() . 'views/');
    }

    // ---------------------------------------------------------------------
    // Menu link to the settings page
    // ---------------------------------------------------------------------

    public function defaultMenuOrder(): int
    {
        return 99;
    }

    public function getMenu(Tree $tree): ?Menu
    {
        if (!Auth::check()) {
            return null;
        }

        return new Menu(
            I18N::translate('2FA'),
            $this->settingsUrl(),
            'menu-two-factor'
        );
    }

    // ---------------------------------------------------------------------
    // Login form: add an "Authentication code" box
    // ---------------------------------------------------------------------

    public function bodyContent(): string
    {
        if (Auth::check()) {
            return '';
        }

        $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
        $label = json_encode(I18N::translate('Authentication code'), $flags) ?: '""';
        $help  = json_encode(I18N::translate('Only needed if you have enabled two-factor authentication.'), $flags) ?: '""';

        $js = <<<'JS'
(function () {
    var pw = document.querySelector('input[name="password"]');
    var user = document.querySelector('input[name="username"]');
    if (!pw || !user || document.querySelector('[name="otp"]')) { return; }
    var form = pw.form;
    if (!form || form !== user.form || !/login/i.test(form.getAttribute('action') || '')) { return; }
    var row = pw.closest('.row') || pw.closest('.mb-3') || pw.parentNode;

    var wrap = document.createElement('div');
    wrap.className = 'mb-3';
    var label = document.createElement('label');
    label.className = 'form-label';
    label.htmlFor = 'otp';
    label.textContent = __LABEL__;
    var input = document.createElement('input');
    input.type = 'text';
    input.id = 'otp';
    input.name = 'otp';
    input.className = 'form-control';
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('autocomplete', 'one-time-code');
    input.setAttribute('maxlength', '10');
    var help = document.createElement('div');
    help.className = 'form-text';
    help.textContent = __HELP__;

    wrap.appendChild(label);
    wrap.appendChild(input);
    wrap.appendChild(help);
    row.parentNode.insertBefore(wrap, row.nextSibling);
})();
JS;

        return '<script>' . str_replace(['__LABEL__', '__HELP__'], [$label, $help], $js) . '</script>';
    }

    // ---------------------------------------------------------------------
    // Middleware: enforce the code when logging in
    // ---------------------------------------------------------------------

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $route = $request->getAttribute('route');
        $name  = $route instanceof Route ? $route->name : '';

        if ($request->getMethod() === 'POST' && $name === LoginAction::class) {
            $failure = $this->checkLoginCode($request);

            if ($failure !== null) {
                return $failure;
            }
        }

        return $handler->handle($request);
    }

    /**
     * Returns a redirect response if the login must be refused, or null to let it continue.
     */
    private function checkLoginCode(ServerRequestInterface $request): ?ResponseInterface
    {
        $params   = (array) $request->getParsedBody();
        $username = trim((string) ($params['username'] ?? ''));
        $password = (string) ($params['password'] ?? '');
        $otp      = preg_replace('/\D/', '', (string) ($params['otp'] ?? '')) ?? '';
        $url      = (string) ($params['url'] ?? '');

        if ($username === '') {
            return null;
        }

        $user = Registry::container()->get(UserService::class)->findByIdentifier($username);

        // Unknown user, 2FA not enabled, or wrong password: let webtrees handle it as normal.
        if ($user === null || !$this->twoFactorEnabled($user) || !$user->checkPassword($password)) {
            return null;
        }
        // Locked out after too many wrong codes: refuse without even checking this one.
        $wait = $this->lockSecondsRemaining($user);

        if ($wait > 0) {
            FlashMessages::addMessage($this->lockMessage($wait), 'danger');

            return Registry::responseFactory()->redirectUrl(route(LoginPage::class, ['url' => $url]));
        }

        $secret = $user->getPreference(self::PREF_SECRET);
        $last   = (int) $user->getPreference(self::PREF_LAST, '0');
        $result = false;

        if ($otp !== '') {
            $result = (new Google2FA())->verifyKeyNewer($secret, $otp, $last, 1);
        }

        if ($result === false) {
            $this->recordFailure($user);

            FlashMessages::addMessage(I18N::translate('The authentication code is missing or incorrect.'), 'danger');

            return Registry::responseFactory()->redirectUrl(route(LoginPage::class, ['url' => $url]));
        }

        $this->clearFailures($user);

        if (is_int($result)) {
            $user->setPreference(self::PREF_LAST, (string) $result);
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Settings page (module actions: getSettingsAction / postSettingsAction)
    // ---------------------------------------------------------------------

    public function getSettingsAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!Auth::check()) {
            return Registry::responseFactory()->redirectUrl(route(LoginPage::class, ['url' => $this->settingsUrl()]));
        }

        $user    = Auth::user();
        $enabled = $this->twoFactorEnabled($user);
        $qr      = '';
        $secret  = '';

        if (!$enabled) {
            $google2fa = new Google2FA();
            $secret    = (string) Session::get(self::SESSION_KEY, '');

            if ($secret === '') {
                $secret = $google2fa->generateSecretKey();
                Session::put(self::SESSION_KEY, $secret);
            }

            $issuer = (string) parse_url((string) $request->getAttribute('base_url'), PHP_URL_HOST);
            $uri    = $google2fa->getQRCodeUrl($issuer !== '' ? $issuer : 'webtrees', $user->userName(), $secret);

            $options = new QROptions([
                'outputType'  => QRCode::OUTPUT_MARKUP_SVG,
                'eccLevel'    => QRCode::ECC_M,
                'imageBase64' => true,
            ]);

            $qr = (new QRCode($options))->render($uri);
        }
        // The page layout needs a tree, but module URLs don't carry one, so pick the site default.
        $tree = $request->getAttribute('tree');

        if (!$tree instanceof Tree) {
            $trees = Registry::container()->get(TreeService::class)->all();
            $tree  = $trees->get(Site::getPreference('DEFAULT_GEDCOM')) ?? $trees->first();
        }

        return $this->viewResponse($this->name() . '::settings', [
            'title'      => I18N::translate('Two-factor authentication'),
            'tree'       => $tree,
            'enabled'    => $enabled,
            'qr'         => $qr,
            'secret'     => $secret,
            'action_url' => $this->settingsUrl(),
        ]);	

    }

    public function postSettingsAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!Auth::check()) {
            return Registry::responseFactory()->redirectUrl(route(LoginPage::class));
        }

        $user   = Auth::user();
        $params = (array) $request->getParsedBody();
        $task   = (string) ($params['task'] ?? '');
        $otp    = preg_replace('/\D/', '', (string) ($params['otp'] ?? '')) ?? '';
        $g2fa   = new Google2FA();

        if ($task === 'enable' && !$this->twoFactorEnabled($user)) {
            $secret = (string) Session::get(self::SESSION_KEY, '');

            if ($secret !== '' && $otp !== '' && $g2fa->verifyKey($secret, $otp, 1)) {
                $user->setPreference(self::PREF_SECRET, $secret);
                $user->setPreference(self::PREF_LAST, '0');
                $user->setPreference(self::PREF_ENABLED, '1');
                Session::forget(self::SESSION_KEY);
                FlashMessages::addMessage(I18N::translate('Two-factor authentication is now enabled.'), 'success');
            } else {
                FlashMessages::addMessage(I18N::translate('That code was not correct. Please try again.'), 'danger');
            }
       } elseif ($task === 'disable' && $this->twoFactorEnabled($user)) {
            $wait = $this->lockSecondsRemaining($user);

            if ($wait > 0) {
                FlashMessages::addMessage($this->lockMessage($wait), 'danger');
            } else {
                $secret = $user->getPreference(self::PREF_SECRET);

                if ($otp !== '' && $g2fa->verifyKey($secret, $otp, 1)) {
                    $user->setPreference(self::PREF_ENABLED, '0');
                    $user->setPreference(self::PREF_SECRET, '');
                    $user->setPreference(self::PREF_LAST, '0');
                    $this->clearFailures($user);
                    FlashMessages::addMessage(I18N::translate('Two-factor authentication has been disabled.'), 'success');
                } else {
                    $this->recordFailure($user);
                    FlashMessages::addMessage(I18N::translate('That code was not correct. Please try again.'), 'danger');
                }
            }
       }

        return Registry::responseFactory()->redirectUrl($this->settingsUrl());
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private function settingsUrl(): string
    {
        return route('module', ['module' => $this->name(), 'action' => 'Settings']);
    }

    /**
     * @param \Fisharebest\Webtrees\Contracts\UserInterface $user
     */
    private function twoFactorEnabled(UserInterface $user): bool
    {
        return $user->getPreference(self::PREF_ENABLED) === '1'
            && $user->getPreference(self::PREF_SECRET) !== '';
    }
    /**
     * Seconds remaining on a lock, or 0 if not locked.
     */
    private function lockSecondsRemaining(UserInterface $user): int
    {
        return max(0, (int) $user->getPreference(self::PREF_LOCKED_UNTIL, '0') - time());
    }

    private function recordFailure(UserInterface $user): void
    {
        $failures = (int) $user->getPreference(self::PREF_FAILURES, '0') + 1;

        if ($failures >= self::MAX_FAILURES) {
            $user->setPreference(self::PREF_LOCKED_UNTIL, (string) (time() + self::LOCK_SECONDS));
            $failures = 0;
        }

        $user->setPreference(self::PREF_FAILURES, (string) $failures);
    }

    private function clearFailures(UserInterface $user): void
    {
        $user->setPreference(self::PREF_FAILURES, '0');
        $user->setPreference(self::PREF_LOCKED_UNTIL, '0');
    }

    private function lockMessage(int $seconds): string
    {
        $minutes = (int) ceil($seconds / 60);

        return I18N::plural(
            'Too many incorrect codes. Please try again in %s minute.',
            'Too many incorrect codes. Please try again in %s minutes.',
            $minutes,
            I18N::number($minutes)
        );
    }    
}

