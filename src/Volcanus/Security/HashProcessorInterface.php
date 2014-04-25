<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security;

/**
 * ハッシュ処理インタフェース
 *
 * @author k.holy74@gmail.com
 */
interface HashProcessorInterface
{

	/**
	 * 文字列を非可逆ハッシュ化して返します。
	 *
	 * @param string 文字列
	 * @param string ハッシュソルト
	 * @return string 文字列ハッシュ
	 */
	public function hash($data, $salt = null);

	/**
	 * ランダム文字列を生成します。
	 *
	 * @param string ランダム文字列に利用する文字
	 * @param int ランダム文字列の桁数
	 * @return string ランダム文字列
	 */
	public function createRandom($length = null, $chars = null);

	/**
	 * オブジェクトの文字列表現を返します。
	 *
	 * @return string
	 */
	public function __toString();

}
