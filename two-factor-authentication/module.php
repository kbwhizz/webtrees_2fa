<?php

declare(strict_types=1);

namespace TwoFactorAuthentication;

// Load the bundled libraries (pragmarx/google2fa, chillerlan/php-qrcode).
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

require __DIR__ . '/TwoFactorAuthentication.php';

// This script must return an object that implements ModuleCustomInterface.
// If the module's constructor does not take any parameters, you can simply instantiate it.
//
// If you are using dependency-injection in your module, you would ask webtrees to make the object for you.
// return Webtrees::make(ExampleModule::class);
// For an example, see the server-config module.

return new TwoFactorAuthentication();

