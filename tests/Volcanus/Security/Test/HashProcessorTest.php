<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security\Test;

use Volcanus\Security\HashProcessor;

/**
 * Test for HashProcessor
 *
 * @author k.holy74@gmail.com
 */
class HashProcessorTest extends \PHPUnit_Framework_TestCase
{

	public function testCreateRandom()
	{
		$processor = new HashProcessor(array(
			'randomLength' => 500,
			'randomChars'  => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
		));
		$random = $processor->createRandom();
		$this->assertEquals(500, strlen($random));
		$this->assertTrue(strspn($random, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') === strlen($random));
	}

	public function testHashIsMatch()
	{
		$processor1 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		$processor2 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		// 同一アルゴリズム、同一ストレッチ回数、同一データ、同一ソルトの結果は等しい
		$this->assertEquals(
			$processor1->hash('develop', 'test'),
			$processor2->hash('develop', 'test')
		);
		$this->assertEquals(
			$processor1->hash('foo', 'bar'),
			$processor2->hash('foo', 'bar')
		);
	}

	public function testHashIsNotMatchWhenDataIsNotSame()
	{
		$processor1 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		$processor2 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		// 異なるデータ
		$this->assertNotEquals(
			$processor1->hash('develop', 'test'),
			$processor2->hash('another_develop', 'test')
		);
	}

	public function testHashIsNotMatchWhenSaltIsNotSame()
	{
		$processor1 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		$processor2 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		// 異なったソルト
		$this->assertNotEquals(
			$processor1->hash('develop', 'test'),
			$processor2->hash('develop', 'another_test')
		);
	}

	public function testHashIsNotMatchWhenAlgorhythmIsNotSame()
	{
		$processor1 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		$processor2 = new HashProcessor(array(
			'algorithm'       => 'sha384',
			'stretchingCount' => 100,
		));

		// 異なったアルゴルズム
		$this->assertNotEquals(
			$processor1->hash('develop', 'test'),
			$processor2->hash('develop', 'test')
		);
	}

	public function testHashIsNotMatchWhenStretchingCountIsNotSame()
	{
		$processor1 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 100,
		));

		$processor2 = new HashProcessor(array(
			'algorithm'       => 'sha256',
			'stretchingCount' => 10,
		));

		// 異なったストレッチ回数
		$this->assertNotEquals(
			$processor1->hash('develop', 'test'),
			$processor2->hash('develop', 'test')
		);
	}

	/**
	 * @expectedException \RuntimeException
	 */
	public function testHashRaiseExceptionWhenUnsupportedAlgorhythm()
	{
		$processor = new HashProcessor(array(
			'algorithm'       => 'unsupported-algorithm',
			'stretchingCount' => 100,
		));
		$processor->hash('develop', 'test');
	}

}
