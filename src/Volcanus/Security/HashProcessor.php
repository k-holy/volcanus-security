<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security;

/**
 * ハッシュ処理クラス
 *
 * @author k.holy74@gmail.com
 */
class HashProcessor implements HashProcessorInterface
{

	/**
	 * @var array 設定値
	 */
	private $config;

	/**
	 * コンストラクタ
	 *
	 * @param array | ArrayAccess 設定オプション
	 */
	public function __construct($configurations = array())
	{
		$this->initialize($configurations);
	}

	/**
	 * オブジェクトを初期化します。
	 *
	 * @param array | ArrayAccess 設定オプション
	 */
	public function initialize($configurations = array())
	{
		$this->config = array();
		$this->config['algorithm'      ] = 'sha256';
		$this->config['stretchingCount'] = 0;
		$this->config['saltLength'     ] = 64;
		$this->config['saltChars'      ] = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		$this->config['randomChars'    ] = 10;
		$this->config['randomLength'   ] = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&+-./:=?[]_';
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
				case 'algorithm':
				case 'saltChars':
				case 'randomChars':
					if (!is_string($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config parameter "%s" only accepts string.', $name));
					}
					break;
				case 'stretchingCount':
				case 'saltLength':
				case 'randomLength':
					if (!is_int($value) && !ctype_digit($value)) {
						throw new \InvalidArgumentException(
							sprintf('The config parameter "%s" only accepts numeric.', $name));
					}
					$value = intval($value);
					break;
				default:
					throw new \InvalidArgumentException(
						sprintf('The config parameter "%s" is not defined.', $name)
					);
				}
				$this->config[$name] = $value;
			}
			return $this;
		}
		throw new \InvalidArgumentException('Invalid argument count.');
	}

	/**
	 * 文字列を非可逆ハッシュ化して返します。
	 *
	 * @param string 文字列
	 * @param string ハッシュソルト
	 * @return string 文字列ハッシュ
	 */
	public function hash($data, $salt = null)
	{
		if ($salt === null) {
			$salt = $this->createRandom(
				$this->config('saltLength'),
				$this->config('saltChars')
			);
		}

		$stretchingCount = $this->config('stretchingCount');
		$algorithm = $this->config('algorithm');

		$supportedAlgos = array();
		$supportedAlgos += hash_algos();
		if (!in_array($algorithm, $supportedAlgos)) {
			throw new \RuntimeException(
				sprintf('The algorithm "%s" is not support.', $algorithm)
			);
		}

		$hashed = $data;
		for ($i = 0; $i < $stretchingCount; $i++) {
			$hashed = hash($algorithm, $hashed . $data . $salt, false);
		}

		return $hashed;
	}

	/**
	 * ランダム文字列を生成します。
	 *
	 * @param string ランダム文字列に利用する文字
	 * @param int ランダム文字列の桁数
	 * @return string ランダム文字列
	 */
	public function createRandom($length = null, $chars = null)
	{
		if ($length === null) {
			$length = $this->config('randomLength');
		}

		if (empty($length)) {
			throw new \RuntimeException('Unspecified length for random().');
		}

		if ($chars === null) {
			$chars = $this->config('randomChars') ?: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		}

		if (strlen($chars) === 0) {
			throw new \RuntimeException('Unspecified characters for random().');
		}

		return self::createRandomString($length, $chars);
	}

	/**
	 * オブジェクトの文字列表現を返します。
	 *
	 * @return string
	 */
	public function __toString()
	{
		return print_r(
			array(
				'class' => get_class($this),
				'config' => $this->config,
			),
			true
		);
	}

	private function createRandomString($length, $chars)
	{
		$string = '';
		$max = strlen($chars) - 1;
		for ($i = 0; $i < $length; $i++) {
			$string .= $chars[mt_rand(0, $max)];
		}
		return $string;
	}

}
