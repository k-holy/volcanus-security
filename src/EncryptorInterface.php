<?php
/**
 * セキュリティ
 *
 * @copyright k-holy <k.holy74@gmail.com>
 * @license The MIT License (MIT)
 */

namespace Volcanus\Security;

/**
 * 暗号化処理インタフェース
 *
 * @author k.holy74@gmail.com
 */
interface EncryptorInterface
{

	/**
	 * 文字列を暗号化して返します。
	 * key, ivには暗号化時・復号時とも同じ値を入力すること。
	 *
	 * @param string 暗号化する文字列
	 * @param string 暗号キー
	 * @param string 暗号初期化ベクトル(IV)
	 * @return string 暗号化結果
	 */
	public function encrypt($data, $key = null, $iv = null);

	/**
	 * 暗号化された文字列を復号して返します。
	 * key, ivには暗号化時・復号時とも同じ値を入力すること。
	 *
	 * @param string 復号する文字列
	 * @param string 暗号キー
	 * @param string 暗号初期化ベクトル(IV)
	 * @return string 復号結果
	 */
	public function decrypt($encrypted, $key = null, $iv = null);

}
