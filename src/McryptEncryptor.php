<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security;

/**
 * Mcrypt暗号化処理クラス
 *
 * @author k.holy74@gmail.com
 */
class McryptEncryptor implements EncryptorInterface
{

	const PADDING_PKCS7 = 'pkcs7';
	const PADDING_NULL  = 'null';

	/**
	 * @var array 設定値
	 */
	private $config;

	/**
	 * @var resource 暗号モジュール
	 */
	private $module;

	/**
	 * コンストラクタ
	 *
	 * @param array | ArrayAccess 設定オプション
	 */
	public function __construct($configurations = array())
	{
		if (!function_exists('mcrypt_module_open')) {
			throw new \RuntimeException('This class needs mcrypt module.');
		}
		$this->initialize($configurations);
	}

	/**
	 * デストラクタ
	 * 暗号化ハンドルをクローズします。
	 */
	public function __destruct()
	{
		if (isset($this->module) && is_resource($this->module)) {
			mcrypt_module_close($this->module);
		}
	}

	/**
	 * オブジェクトを初期化します。
	 *
	 * @param array | ArrayAccess 設定オプション
	 */
	public function initialize($configurations = array())
	{
		$this->module = null;
		$this->config = array();
		$this->config['base64Encode'] = true;
		$this->config['algorithm'] = null;
		$this->config['mode'] = null;
		$this->config['padding'] = self::PADDING_NULL;
		$this->config['key'] = null;
		$this->config['iv'] = null;
		$this->config['saltLength'] = 0;
		if (!empty($configurations)) {
			foreach ($configurations as $name => $value) {
				$this->config($name, $value);
			}
		}
		return $this;
	}

	/**
	 * 引数1の場合は指定された設定の値を返します。
	 * 引数2の場合は指定された設置の値をセットして$thisを返します。
	 *
	 * @param string 設定名
	 * @return mixed 設定値 または $this
	 */
	public function config($name)
	{
		switch (func_num_args()) {
		case 1:
			return $this->config[$name];
		case 2:
			$value = func_get_arg(1);
			if (isset($value)) {
				switch ($name) {
				case 'padding':
				case 'key':
				case 'iv':
					if (!is_string($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config "%s" only accepts string.', $name));
					}
					break;
				case 'saltLength':
					if (!is_int($value) && !ctype_digit($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config "%s" only accepts numeric.', $name));
					}
					$value = intval($value);
					break;
				case 'base64Encode':
					if (!is_int($value) && !ctype_digit($value) && !is_bool($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config "%s" only accepts numeric.', $name));
					}
					$value = (bool)$value;
					break;
				case 'algorithm':
					if (!is_string($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config "%s" only accepts string.', $name));
					}
					$supported_list = mcrypt_list_algorithms();
					if (!in_array($value, $supported_list)) {
						throw new \InvalidArgumentException(
							sprintf('The algorithm "%s" is not supported.', $value)
						);
					}
					break;
				case 'mode':
					if (!is_string($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config "%s" only accepts string.', $name));
					}
					$supported_list = mcrypt_list_modes();
					if (!in_array($value, $supported_list)) {
						throw new \InvalidArgumentException(
							sprintf('The mode "%s" is not supported.', $value)
						);
					}
					break;
				default:
					throw new \InvalidArgumentException(
						sprintf('The config "%s" is not defined.', $name)
					);
				}
				$this->config[$name] = $value;
			}
			return $this;
		}
		throw new \InvalidArgumentException('Invalid argument count.');
	}

	/**
	 * 設定に合わせた暗号キーのサイズを返します。
	 *
	 * @return int 暗号キーのサイズ
	 */
	public function getKeySize()
	{
		return mcrypt_enc_get_key_size($this->getModule());
	}

	/**
	 * 設定に合わせた暗号キーの値をランダムで生成します。
	 *
	 * @return string 暗号キー
	 */
	public function createKey()
	{
		return $this->createRandomBytes($this->getKeySize());
	}

	/**
	 * 設定に合わせた暗号初期化ベクトル(IV)のサイズを返します。
	 *
	 * @return int 暗号初期化ベクトル(IV)のサイズ
	 */
	public function getIvSize()
	{
		return mcrypt_enc_get_iv_size($this->getModule());
	}

	/**
	 * 設定に合わせた暗号初期化ベクトル(IV)の値をランダムで生成します。
	 *
	 * @return string 暗号初期化ベクトル(IV)
	 */
	public function createIv()
	{
		return $this->createRandomBytes($this->getIvSize());
	}

	/**
	 * 文字列を暗号化して返します。
	 * key, ivには暗号化時・復号時とも同じ値を入力すること。
	 *
	 * @param string 暗号化する文字列
	 * @param string 暗号キー
	 * @param string 暗号初期化ベクトル(IV)
	 * @return string 暗号化結果
	 */
	public function encrypt($data, $key = null, $iv = null)
	{
		$module = $this->initModule($key, $iv);
		$toEncrypt = $this->pad($data);
		$encrypted = mcrypt_generic($module, $toEncrypt);
		mcrypt_generic_deinit($module);
		$saltLength = $this->config('saltLength');
		if (!empty($saltLength)) {
			$encrypted = $this->createRandomBytes($saltLength) . $encrypted;
		}
		return ($this->config('base64Encode')) ? base64_encode($encrypted) : $encrypted;
	}

	/**
	 * 暗号化された文字列を復号して返します。
	 * key, ivには暗号化時・復号時とも同じ値を入力すること。
	 *
	 * @param string 復号する文字列
	 * @param string 暗号キー
	 * @param string 暗号初期化ベクトル(IV)
	 * @return string 復号結果
	 */
	public function decrypt($encrypted, $key = null, $iv = null)
	{
		$module = $this->initModule($key, $iv);
		if ($this->config('base64Encode')) {
			$encrypted = base64_decode($encrypted);
		}
		$saltLength = $this->config('saltLength');
		if (!empty($saltLength)) {
			$encrypted = substr($encrypted, $saltLength);
		}
		$decrypted = mdecrypt_generic($module, $encrypted);
		$decrypted = $this->trim($decrypted);
		mcrypt_generic_deinit($module);
		return $decrypted;
	}

	private function pad($data)
	{
		$blockSize = mcrypt_enc_get_block_size($this->module);
		switch ($this->config('padding')) {
		case self::PADDING_PKCS7:
			$length = $blockSize - (strlen($data) % $blockSize);
			return $data . str_repeat(chr($length), $length);
		case self::PADDING_NULL:
			return str_pad($data, ceil(strlen($data) / $blockSize) * $blockSize, "\0");
		}
		return $data;
	}

	private function trim($data)
	{
		switch ($this->config('padding')) {
		case self::PADDING_PKCS7:
			return substr($data, 0, -1 * ord(substr($data, -1, 1)));
		case self::PADDING_NULL:
			return rtrim($data, "\0");
		}
		return $data;
	}

	private function getModule()
	{
		if (!isset($this->module)) {
			$algorithm = $this->config('algorithm');
			if (is_null($algorithm)) {
				throw new \RuntimeException('Crypt algorithm is not set');
			}
			$mode = $this->config('mode');
			if (is_null($mode)) {
				throw new \RuntimeException('Crypt mode is not set');
			}
			$this->module = mcrypt_module_open($algorithm, '', $mode, '');
		}
		return $this->module;
	}

	private function initModule($key = null, $iv = null)
	{
		$module = $this->getModule();

		if ($key === null || strlen($key) === 0) {
			$key = $this->config('key');
		}
		if ($key === null || strlen($key) === 0) {
			throw new \RuntimeException('Set config "key" for encrypt.');
		}

		if ($iv === null || strlen($iv) === 0) {
			$iv = $this->config('iv');
		}
		if ($iv === null || strlen($iv) === 0) {
			throw new \RuntimeException('Set config "iv" for encrypt.');
		}

		$key_size = mcrypt_enc_get_key_size($module);
		if (strlen($key) > $key_size) {
			throw new \InvalidArgumentException(
				sprintf('Key must be less than %d characters (bytes).', $key_size));
		}

		$iv_size = mcrypt_enc_get_iv_size($module);
		if ($iv_size != 0 && strlen($iv) != $iv_size) {
			throw new \InvalidArgumentException(
				sprintf('IV must be %d characters (bytes).', $iv_size));
		}

		$result = mcrypt_generic_init($module, $key, $iv);
		if ((is_int($result) && $result < 0) || $result === false) {
			throw new \RuntimeException(
				sprintf('mcrypt_generic_init() failed. error:%s', $result)
			);
		}

		return $module;
	}

	private function createRandomBytes($length)
	{
		return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
	}

}
