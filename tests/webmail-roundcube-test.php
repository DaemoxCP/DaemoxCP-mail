<?php
/*
 * Roundcube's real code against the running mail panel: the httpapi driver of the password
 * plugin (plugins/password/drivers/httpapi.php, with Roundcube's own Guzzle) reading the block the
 * panel writes into config.inc.php, and the login_after hook of the panel's mailpanel_sso plugin.
 * Only the few rcube methods they call are stubbed, the same way Roundcube implements them.
 *
 * Run by MailboxPasswordTest when -Droundcube.dir=... points to an unpacked
 * roundcubemail-1.6.x-complete. Arguments:
 *   roundcube_dir config_file plugin_file email current_password new_password vault_url vault_key
 */
[, $rc, $configFile, $pluginFile, $email, $current, $new, $vaultUrl, $vaultKey] = $argv;
require $rc . '/vendor/autoload.php';

define('PASSWORD_CRYPT_ERROR', 1);
define('PASSWORD_ERROR', 2);
define('PASSWORD_CONNECT_ERROR', 3);
define('PASSWORD_IN_HISTORY', 4);
define('PASSWORD_CONSTRAINT_VIOLATION', 5);
define('PASSWORD_COMPARE_CURRENT', 6);
define('PASSWORD_COMPARE_NEW', 7);
define('PASSWORD_SUCCESS', 0);

class StubConfig
{
    public $prop = [];
    function get($name, $default = null) { return $this->prop[$name] ?? $default; }
}

class rcube
{
    public static $instance;
    public $config;
    public $userName;
    public $userPassword;
    public $logs = [];

    static function get_instance() { return self::$instance; }
    // as in program/lib/Roundcube/rcube.php
    function get_http_client($options = []) { return new \GuzzleHttp\Client($options + $this->config->get('http_client', [])); }
    static function raise_error($arg, $log = false, $terminate = false) { self::$instance->logs[] = is_array($arg) ? $arg['message'] : (string) $arg; }
    static function write_log($name, $line) { self::$instance->logs[] = $line; }
    function get_user_name() { return $this->userName; }
    function get_user_password() { return $this->userPassword; }
}

class rcmail extends rcube {}

// as in plugins/password/password.php
class password
{
    static function get_http_client()
    {
        $rcube = rcube::get_instance();
        return $rcube->get_http_client((array) $rcube->config->get('password_http_client'));
    }
}

class rcube_plugin
{
    function load_config() {}
    function add_hook($name, $callback) {}
}

$config = [];
include $configFile;    // the file as Roundcube reads it, with the panel's block at the end
rcube::$instance = new rcmail();
rcube::$instance->config = new StubConfig();
rcube::$instance->config->prop = $config;
echo 'driver:' . ($config['password_driver'] ?? '') . "\n";

require $rc . '/plugins/password/drivers/httpapi.php';
$driver = new rcube_httpapi_password();
echo 'wrong_current:' . $driver->save('Not-The-Current-2026', 'Another-New-2026', $email) . "\n";
echo 'change:' . $driver->save($current, $new, $email) . "\n";

require $pluginFile;
$plugin = new mailpanel_sso();
rcube::$instance->config->prop['mailpanel_vault_url'] = $vaultUrl;
rcube::$instance->config->prop['mailpanel_vault_key'] = $vaultKey;
rcube::$instance->userName = $email;
rcube::$instance->userPassword = $new;
$plugin->login_after(['_task' => 'mail']);
echo "hook:done\n";
rcube::$instance->config->prop['mailpanel_vault_url'] = 'https://127.0.0.1:1/api/internal/mailbox-vault';
$plugin->login_after(['_task' => 'mail']);
echo "hook_unreachable:done\n";
foreach (rcube::$instance->logs as $line) echo 'log:' . $line . "\n";
