<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security\Test;

use Volcanus\Security\McryptEncryptor;

/**
 * Test for McryptEncryptor
 *
 * @author k.holy74@gmail.com
 */
class McryptEncryptorTest extends \PHPUnit_Framework_TestCase
{

	private function createEncryptee()
	{
		return mcrypt_create_iv(4096, MCRYPT_DEV_URANDOM);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testRaiseExceptionWhenUnsupportedAlgorithmWasSpecified()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => 'unsupported-algorithm',
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testRaiseExceptionWhenUnsupportedModeWasSpecified()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => 'unsupported-mode',
			'base64Encode' => true,
		));
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigPaddingRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('padding', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigKeyRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('key', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigIvRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('iv', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigSaltLengthRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('saltLength', 'true');
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigBase64EncodeRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('base64Encode', 'true');
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigAlgorithmRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('algorithm', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testRaiseInvalidArgumentExceptionWhenUnsupportedConfigKey()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('unsupportedConfigKey', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testConfigModeRaiseInvalidArgumentException()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('mode', 1);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testRaiseInvalidArgumentExceptionWhenInvalidArgumentCount()
	{
		$encryptor = new McryptEncryptor();
		$encryptor->config('saltLength', 1, 2);
	}

	public function testCreateKey()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey();
		$this->assertEquals($encryptor->getKeySize(), strlen($key));
	}

	public function testCreateIv()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$iv = $encryptor->createIv();
		$this->assertEquals($encryptor->getIvSize(), strlen($iv));
	}

	public function testEncryptAndDecrypt()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$encryptor->decrypt(
				$encryptor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	public function testEncryptAndDecryptByConfig()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$encryptor->config('key', $encryptor->createKey());
		$encryptor->config('iv', $encryptor->createIv());

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$encryptor->decrypt(
				$encryptor->encrypt($encryptee)
			)
		);
	}

	public function testEncryptAndDecryptWithSalt()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'saltLength'   => 16,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$encryptor->decrypt(
				$encryptor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	public function testEncryptAndDecryptPaddingPkcs7()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => McryptEncryptor::PADDING_PKCS7,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$encryptor->decrypt(
				$encryptor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	public function testEncryptAndDecryptNoPadding()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$encryptor->decrypt(
				$encryptor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	/**
	 * アルゴリズム、モード、Key、CriptIvが同一の設定で暗号化した結果は同じ
	 */
	public function testEncryptIsMatchWhenSameKeyAndIv()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptor->encrypt($encryptee, $key, $iv),
			$encryptor2->encrypt($encryptee, $key, $iv)
		);

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptor->encrypt($encryptee, $key, $iv),
			$encryptor2->encrypt($encryptee, $key, $iv)
		);
	}

	/**
	 * アルゴリズム、モード、Key、CriptIvが同一の設定で暗号化した結果は同じ
	 */
	public function testEncryptIsMatchWhenSameKeyAndIvByConfig()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptor->config('key', $key);
		$encryptor->config('iv', $iv);

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'key' => $key,
			'iv' => $iv,
		));

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptor->encrypt($encryptee),
			$encryptor2->encrypt($encryptee)
		);

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptor->encrypt($encryptee),
			$encryptor2->encrypt($encryptee)
		);
	}

	/**
	 * Keyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenKeyIsNotSame()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $encryptor->createIv();

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'iv'      => $iv,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$encryptor->encrypt($encryptee, $encryptor->createKey(), $iv),
			$encryptor2->encrypt($encryptee, $encryptor2->createKey(), $iv)
		);
	}

	/**
	 * Keyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenKeyIsNotSameByConfig()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $encryptor->createIv();

		$encryptor->config('key', $encryptor->createKey());
		$encryptor->config('iv', $iv);

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'iv' => $iv,
		));
		$encryptor2->config('key', $encryptor2->createKey());

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$encryptor->encrypt($encryptee),
			$encryptor2->encrypt($encryptee)
		);
	}

	/**
	 * Ivが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenIvIsNotSame()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$encryptor->encrypt($encryptee, $key, $encryptor->createIv()),
			$encryptor2->encrypt($encryptee, $key, $encryptor2->createIv())
		);
	}

	/**
	 * Ivが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenIvIsNotSameByConfig()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();

		$encryptor->config('key', $key);
		$encryptor->config('iv', $encryptor->createIv());

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'key' => $key,
		));
		$encryptor2->config('iv', $encryptor2->createIv());

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$encryptor->encrypt($encryptee),
			$encryptor2->encrypt($encryptee)
		);
	}

	/**
	 * ブロック暗号モードが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenModeIsNotSame()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();

		$encryptor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$encryptor->encrypt($encryptee, $key, $iv),
			$encryptor2->encrypt($encryptee, $key, $iv)
		);
	}

	/**
	 * @expectedException \RuntimeException
	 */
	public function testEncryptRaiseRuntimeExceptionWhenAlgorithmIsNotSet()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => null,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

	/**
	 * @expectedException \RuntimeException
	 */
	public function testEncryptRaiseRuntimeExceptionWhenModeIsNotSet()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => null,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv();
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

	/**
	 * @expectedException \RuntimeException
	 */
	public function testEncryptRaiseRuntimeExceptionWhenKeyIsNotSpecified()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = null;
		$iv  = $encryptor->createIv();
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

	/**
	 * @expectedException \RuntimeException
	 */
	public function testEncryptRaiseRuntimeExceptionWhenIvIsNotSpecified()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey();
		$iv = null;
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testEncryptRaiseInvalidArgumentExceptionWhenKeySizeOver()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey() . 'a';
		$iv  = $encryptor->createIv();
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

	/**
	 * @expectedException \InvalidArgumentException
	 */
	public function testEncryptRaiseInvalidArgumentExceptionWhenIvSizeOver()
	{
		$encryptor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => null,
			'base64Encode' => true,
		));
		$key = $encryptor->createKey();
		$iv  = $encryptor->createIv() . 'a';
		$encryptor->encrypt($this->createEncryptee(), $key, $iv);
	}

}
