<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security\Test\Crypt;

use Volcanus\Security\Crypt\McryptEncryptor;

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
		$processor = new McryptEncryptor(array(
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
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => 'unsupported-mode',
			'base64Encode' => true,
		));
	}

	public function testCreateKey()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$key = $processor->createKey();
		$this->assertEquals($processor->getKeySize(), strlen($key));
	}

	public function testCreateIv()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$iv = $processor->createIv();
		$this->assertEquals($processor->getIvSize(), strlen($iv));
	}

	public function testEncryptAndDecrypt()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$processor->decrypt(
				$processor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	public function testEncryptAndDecryptByConfig()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$processor->config('key', $processor->createKey());
		$processor->config('iv', $processor->createIv());

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$processor->decrypt(
				$processor->encrypt($encryptee)
			)
		);
	}

	public function testEncryptAndDecryptWithSalt()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'saltLength'   => 16,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$processor->decrypt(
				$processor->encrypt($encryptee, $key, $iv),
				$key,
				$iv
			)
		);
	}

	public function testEncryptAndDecryptPaddingPkcs7()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => McryptEncryptor::PADDING_PKCS7,
			'base64Encode' => true,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$encryptee,
			$processor->decrypt(
				$processor->encrypt($encryptee, $key, $iv),
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
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$processor->encrypt($encryptee, $key, $iv),
			$processor2->encrypt($encryptee, $key, $iv)
		);

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$processor->encrypt($encryptee, $key, $iv),
			$processor2->encrypt($encryptee, $key, $iv)
		);
	}

	/**
	 * アルゴリズム、モード、Key、CriptIvが同一の設定で暗号化した結果は同じ
	 */
	public function testEncryptIsMatchWhenSameKeyAndIvByConfig()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$processor->config('key', $key);
		$processor->config('iv', $iv);

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'key' => $key,
			'iv' => $iv,
		));

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$processor->encrypt($encryptee),
			$processor2->encrypt($encryptee)
		);

		$encryptee = $this->createEncryptee();

		$this->assertEquals(
			$processor->encrypt($encryptee),
			$processor2->encrypt($encryptee)
		);
	}

	/**
	 * Keyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenKeyIsNotSame()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $processor->createIv();

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'iv'      => $iv,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee, $processor->createKey(), $iv),
			$processor2->encrypt($encryptee, $processor2->createKey(), $iv)
		);
	}

	/**
	 * Keyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenKeyIsNotSameByConfig()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $processor->createIv();

		$processor->config('key', $processor->createKey());
		$processor->config('iv', $iv);

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'iv' => $iv,
		));
		$processor2->config('key', $processor2->createKey());

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee),
			$processor2->encrypt($encryptee)
		);
	}

	/**
	 * Ivが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenIvIsNotSame()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee, $key, $processor->createIv()),
			$processor2->encrypt($encryptee, $key, $processor2->createIv())
		);
	}

	/**
	 * Ivが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenIvIsNotSameByConfig()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();

		$processor->config('key', $key);
		$processor->config('iv', $processor->createIv());

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'key' => $key,
		));
		$processor2->config('iv', $processor2->createIv());

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee),
			$processor2->encrypt($encryptee)
		);
	}

	/**
	 * ブロック暗号モードが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenModeIsNotSame()
	{
		$processor = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createKey();
		$iv  = $processor->createIv();

		$processor2 = new McryptEncryptor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee, $key, $iv),
			$processor2->encrypt($encryptee, $key, $iv)
		);
	}

}
