# DNS dynamic updater for NSD

## はじめに

私は nsd を使っていますが、nsd は動的更新に対応していません。
なので、zone file を直接いじっちゃえ、ってことで、
dhcpd からの動的更新リクエストを受け取って nsd の zone file
を更新して nsd を reload する script を書いてみました。

## インストール

1. `ddns-nsd.rb` をどこかに置いて下さい。
2. `ddns-nsd.service`, `ddns-nsd.socket` を `/etc/systemd/system/` にコピーしてください。
3. 以下の説明に従い、`/etc/nsd/ddns-nsd.yml` を作成してください。
4. ここまで完了したら、ddns-nsd を起動してください。
   ```sh
   systemctl enable ddns-nsd.socket
   systemctl start ddns-nsd.socket
   ```
5. dhcpd も設定してください。ddns-update-style は standard です。

## `ddns-nsd.yml` の書き方

まず全貌から。

```yaml
json: /etc/nsd/ddns-nsd.json
listen:
  - 127.0.0.2:53
  - [::2]:53
restart_nsd: "systemctl reload nsd"
keys:
  - name: dhcp_updater.
    alg: hmac-md5
    secret: F+qM3Byarsuomm9sgyBWMn+6r2Vbu3RIWBH9U1BxSfQ=
zones:
  - name: pink.masm11.ddo.jp.
    file: /etc/nsd/pink.masm11.ddo.jp.zone
  - name: 168.192.in-addr.arpa.
    file: /etc/nsd/168.192.in-addr.arpa.zone
  - name: 1.0.0.0.8.6.9.8.6.9.0.0.f.0.4.2.ip6.arpa.
    file: /etc/nsd/1.0.0.0.8.6.9.8.6.9.0.0.f.0.4.2.ip6.arpa.zone
history: /etc/nsd/history
```

- json

  内部状態を json 形式でファイルに保存しています。ここにはそのファイル名を指定します。

- listen

  listen する IP アドレスと port を指定します。
  listen と言っていますが、UDP です。

  ddns-nsd.socket から起動する場合、この項目は不要です。
  代わりに ddns-nsd.socket に設定してください。

- restart_nsd

  nsd を reload するためのコマンドを指定します。

- keys

  TSIG に使う共有秘密鍵を指定します。dhcpd と合わせる必要があります。
  name は鍵の名前、alg は hash 値の計算方法、secret は鍵を指定します。

- zones

  zone について記述します。
  name は zone 名、file は zone file のファイル名です。

- history

  ここで指定したディレクトリに zone file の履歴が保存されます。

## dhcpd と ddns-nsd との通信について

私は、

- 物理 nic 上のアドレスは unbound がキャッシュしている
- 127.0.0.1 と ::1 は nsd が待っている

という状態だったので、新たに 127.0.0.2 と ::2 を作り、

- 127.0.0.2:53 と [::2]:53 で ddns-nsd が待っている

という状態にしました。
複数のアドレスで待ち受けできます。

## 共有秘密鍵について

name は末尾の `.` に気をつけてください。
alg は hmac-md5 しか指定できません。
name, alg, secret は dhcpd と合わせる必要があります。

secret については、これから作るのであれば、以下のような感じで作れます。
```sh
dd if=/dev/random bs=1 count=32 | base64
```

## zone file について

SOA 部分は、おそらく以下のような感じになっていると思います。

```
@ IN SOA 〜 〜 (
           2017080336  ; serial number
           28800       ; Refresh
           7200        ; Retry
           60          ; Expire
           60          ; Min TTL
           )
```

ddns-nsd は serial 部分を自動で書き換えていきますので、ddns-nsd に
どこが serial なのかを教えてやる必要があります。
以下のように少し追記してください

```
@ IN SOA 〜 〜 (
           2017080336  ; serial number DDNS-NSD-SERIAL
           28800       ; Refresh
           7200        ; Retry
           60          ; Expire
           60          ; Min TTL
           )
```

ddns-nsd は `DDNS-NSD-SERIAL` と書いてある行の数値を serial と思って書き換えます。
上書きする値は yyyymmddnn です。yyyymmdd は現在の日付、nn は 00〜99 です。
nn は 99 を超えると 00 に戻ってしまいます。

さて、zone file について準備はこれだけなのですが、ddns-nsd を実行すると、以下のような行が現れます。

```
; DDNS-NSD: --- DON'T EDIT THIS LINE AND BELOW MANUALLY. ---
```

ddns-nsd はこの行より下を書き換えていきます。ここから下は手動で書き換えないで下さい。

## dhcpd4 と dhcpd6 の共存

IPv4 と IPv6 で DHCID が異なっていると、片方が登録できてももう片方が登録できません。

私は GNOME3 で NetworkManager + dhclient を使用しています。その場合の設定例を挙げます。

```sh
nmcli con show <ネットワーク名>
```
で現在の状態を表示できます。

DHCP 周りの設定は以下のようになっています。

```
ipv4.dhcp-client-id:                    <client-id>
ipv4.dhcp-timeout:                      0
ipv4.dhcp-send-hostname:                yes
ipv4.dhcp-hostname:                     --
ipv4.dhcp-fqdn:                         --
```

```
ipv6.dhcp-send-hostname:                yes
ipv6.dhcp-hostname:                     <私の FQDN>
```

`<client-id>` 部分は、
```
DHCP6.オプション[1]:                    dhcp6_client_id = <client-id>
```
と出力されていますので、この `<client-id>` を指定します。

設定値を変更するには、

```sh
nmcli con modify <ネットワーク名> <項目名> <値>
```

で、例えば以下のようになります。

```sh
nmcli con modify example-wifi ipv6.dhcp-hostname my.example.com
```

macOS でどう設定すれば同じことができるかはまだ知りません。

## 対応状況

class は IN のみ対応しています。
type は A, AAAA, PTR, DHCID に対応しています。

## ライセンス

GPLv3 とします。COPYING を参照してください。

## 作者

原野裕樹 &lt;masm@masm11.ddo.jp&gt;
