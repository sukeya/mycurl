# MyCurl
[curl](https://curl.se/)のHTTPプロトコルで取得する機能とプロキシを経由する場合の機能を実装したもの。

## 使い方
```
python mycurl.py [options] URL
```
`URL`にはURLを書いてください。httpプロトコルのみ動きます。httpsは動きません。

### オプション
```
--connect-timeout <fractional seconds>
```
タイムアウトの時間を浮動小数点数で設定できます。

```
-o --output <file>
```
取得したHTMLファイルを出力するパスを指定できます。

#### プロキシ
プロキシを利用する場合、以下の2つのオプションが必要です。
```
-u --proxy-user <user:password>
```
BASIC認証を行うプロキシに接続する場合、ユーザー名とパスワードを指定できます。
BASIC認証以外の認証はサポートしていません。

```
-x --proxy [protocol://]host[:port]
```
プロキシサーバーのホスト名を指定できます。