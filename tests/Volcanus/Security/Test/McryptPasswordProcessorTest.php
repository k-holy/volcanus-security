<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security\Test;

use Volcanus\Security\McryptPasswordProcessor;

/**
 * Test for McryptPasswordProcessor
 *
 * @author k.holy74@gmail.com
 */
class McryptPasswordProcessorTest extends \PHPUnit_Framework_TestCase
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
		$processor = new McryptPasswordProcessor(array(
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
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => 'unsupported-mode',
			'base64Encode' => true,
		));
	}

	public function testCreateCryptKey()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$key = $processor->createCryptKey();
		$this->assertEquals($processor->getCryptKeySize(), strlen($key));
	}

	public function testCreateCryptIv()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));
		$iv = $processor->createCryptIv();
		$this->assertEquals($processor->getCryptIvSize(), strlen($iv));
	}

	public function testEncryptAndDecrypt()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

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
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$processor->config('cryptKey', $processor->createCryptKey());
		$processor->config('cryptIv', $processor->createCryptIv());

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
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'saltLength'   => 16,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

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
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'padding'      => McryptPasswordProcessor::PADDING_PKCS7,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

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
	 * アルゴリズム、モード、CryptKey、CriptIvが同一の設定で暗号化した結果は同じ
	 */
	public function testEncryptIsMatchWhenSameCryptKeyAndCryptIv()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

		$processor2 = new McryptPasswordProcessor(array(
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
	 * アルゴリズム、モード、CryptKey、CriptIvが同一の設定で暗号化した結果は同じ
	 */
	public function testEncryptIsMatchWhenSameCryptKeyAndCryptIvByConfig()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

		$processor->config('cryptKey', $key);
		$processor->config('cryptIv', $iv);

		$processor2 = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
			'cryptKey'     => $key,
			'cryptIv'      => $iv,
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
	 * CryptKeyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenCryptKeyIsNotSame()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $processor->createCryptIv();

		$processor2 = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'cryptIv'      => $iv,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee, $processor->createCryptKey(), $iv),
			$processor2->encrypt($encryptee, $processor2->createCryptKey(), $iv)
		);
	}

	/**
	 * CryptKeyが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenCryptKeyIsNotSameByConfig()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$iv  = $processor->createCryptIv();

		$processor->config('cryptKey', $processor->createCryptKey());
		$processor->config('cryptIv', $iv);

		$processor2 = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'cryptIv'      => $iv,
		));
		$processor2->config('cryptKey', $processor2->createCryptKey());

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee),
			$processor2->encrypt($encryptee)
		);
	}

	/**
	 * CryptIvが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenCryptIvIsNotSame()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();

		$processor2 = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
		));

		$encryptee = $this->createEncryptee();

		$this->assertNotEquals(
			$processor->encrypt($encryptee, $key, $processor->createCryptIv()),
			$processor2->encrypt($encryptee, $key, $processor2->createCryptIv())
		);
	}

	/**
	 * CryptIvが異なる設定で暗号化した結果は同一ではない
	 */
	public function testEncryptIsNotMatchWhenCryptIvIsNotSameByConfig()
	{
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();

		$processor->config('cryptKey', $key);
		$processor->config('cryptIv', $processor->createCryptIv());

		$processor2 = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_ECB,
			'base64Encode' => true,
			'cryptKey'     => $key,
		));
		$processor2->config('cryptIv', $processor2->createCryptIv());

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
		$processor = new McryptPasswordProcessor(array(
			'algorithm'    => MCRYPT_BLOWFISH,
			'mode'         => MCRYPT_MODE_CBC,
			'base64Encode' => true,
		));

		$key = $processor->createCryptKey();
		$iv  = $processor->createCryptIv();

		$processor2 = new McryptPasswordProcessor(array(
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
