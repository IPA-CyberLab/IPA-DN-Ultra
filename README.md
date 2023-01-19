﻿# IPA-DN-Ultra ライブラリ リリースノート (更新履歴)
[![Build](https://github.com/IPA-CyberLab/IPA-DN-Ultra/actions/workflows/build_test_linux.yml/badge.svg)](https://github.com/IPA-CyberLab/IPA-DN-Ultra/actions)
[![Build](https://github.com/IPA-CyberLab/IPA-DN-Ultra/actions/workflows/build_test_windows.yml/badge.svg)](https://github.com/IPA-CyberLab/IPA-DN-Ultra/actions)
[![Coverity](https://scan.coverity.com/projects/23476/badge.svg?flat=1)](https://scan.coverity.com/projects/IPA-DN-Ultra-210730)


この更新履歴ファイルの更新は、2022/08/08 で停止しました。  
最新版は、[**https://github.com/IPA-CyberLab/IPA-DN-ThinLib/**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/) に移動しました。


** BETA VERSION UNDER DEVELOPMENT, INCOMPLETE AND BUGGY. USE AT YOUR OWN RISK. Ver 1.0 is scheduled to be released during November 2021. We strongly recommend that you wait until Ver 1.0 is released. ** - This Git repository contains the source code and documentation for the open source version of the Thin Telework System which is under development. 2021-10-31 by Daiyuu Nobori.


## ご案内 - GitHub リポジトリの変更について (2023/01/20)

- 2023/01/20 に rc1 (Release Candidate 1) をリリースしました。
- これに合わせて、**『IPA-DN-Ultra』** という名前の従来の本リポジトリは、[**『IPA-DN-ThinLib』**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/) という名前の新リポジトリに移行しました。
- 新リポジトリの URL は、[**https://github.com/IPA-CyberLab/IPA-DN-ThinLib/**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/) です。
- 新しい README (変更履歴) の URL は、[**https://github.com/IPA-CyberLab/IPA-DN-ThinLib/blob/master/README.md**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/blob/master/README.md) です。
- お手数をおかけしますが、rc1 (2023/01/20) 以降の変更履歴については、上記の新しい GitHub リポジトリをご参照ください。

## [Current Version] beta8preview9

## rc1 以降 (2023/01/20 以降)
- rc1 以降の変更履歴は、[**『IPA-DN-ThinLib』**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/) という名前の新リポジトリに移行しました。
- 新リポジトリの URL は、[**https://github.com/IPA-CyberLab/IPA-DN-ThinLib/**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/) です。
- 新しい README (変更履歴) の URL は、[**https://github.com/IPA-CyberLab/IPA-DN-ThinLib/blob/master/README.md**](https://github.com/IPA-CyberLab/IPA-DN-ThinLib/blob/master/README.md) です。
- お手数をおかけしますが、rc1 (2023/01/20) 以降の変更履歴については、上記の新しい GitHub リポジトリをご参照ください。

## beta8preview9 - 2022/08/08
1. 一部の環境でポリシー規制サーバーの自動検出に失敗する問題があるという報告がありました。そこで、サーバー側設定で「詳細デバッグログ」を有効にしている場合は、「server_log」ディレクトリに保存されるログにポリシー規制サーバーの自動検出の状況 (デバッグメッセージ) を記録するようにしました。

## beta8preview8 - 2022/07/25
1. コントローラが 2 台以上の冗長構成となっている場合で、かつ、アプリケーション側がプロキシサーバーを使用している場合に、最初の接続試行先コントローラの 1 台のコントローラに TCP レイヤでの接続不具合が生じると、他の接続試行先コントローラへの接続への試行をせずに、当該接続不具合が存在している側のコントローラへの接続をし続ける問題を解決しました。また、関係するメモリリークを解消しました。
1. 内部的に使用する暗号ライブラリを OpenSSL 3.0.3 にアップグレードしました。
1. TLS 1.0 / TLS 1.1 / TLS 1.2 / TLS 1.3 のそれぞれを無効にするオプションが効いていない不具合を解決しました。
1. EntryPoint.dat ファイルで UTF-8 BOM が先頭に記載されていたときに無視するようにしました。
1. シン・テレワークシステム 中継ゲートウェイ スタンドアロン版における SMTP による OTP メール送信機能において、SSL/TLS 通信および SMTP 認証に対応しました。
1. シン・テレワークシステム 中継ゲートウェイ スタンドアロン版に Mikaka DDNS Client の組み込みを行ないました。


## beta8preview7 - 2022/02/05
1. ユーザーモードの場合で、かつ Windows 高速スタートアップが有効な場合は、警告メッセージを表示するようにしました。
1. システムディスクの空き容量が 500MB 未満となった場合、起動時に警告メッセージを表示するようにしました。
1. Win32 版のコンパイラのバージョンを Visual Studio 2019 から Visual Studio 2022 に更新しました。

## beta8preview6 - 2021/10/27
1. HTML5 版 Web クライアントにおいて、日本語キーボードで日本語かな入力を行なう際に、ひながなキーの「を」文字が入力できない問題を解決しました。なお、ひらがなキーの「ろ」文字を入力する場合は、Shift + 「ろ」を押す必要があります。
1. 「ユーザーモード リモートデスクトップ」モードにおける重要な制限事項について: 一部のキー入力や特権を伴うキー操作ができない場合があります。日本語入力においてかな入力で一部の文字 (「を」、「ろ」等) が入力できない場合があります。「ユーザーモード リモートデスクトップ」モードでは、ローマ字入力をお使いください。

## beta8preview5 - 2021/10/26
1. HTML5 版 Web クライアントから、クライアントのマイクの共有が可能になりました。これにより、サーバー側 PC 上で動作している Teams や Zoom, Skype, WebEx 等のテレビ会議システムに、クライアント PC のマイクを接続することが可能になります。この機能を有効にするには、サーバーアプリケーションのバージョンを beta8preview5 以降にする必要があります。また、Web ブラウザにおけるマイクの共有機能を有効にする必要があります。Web ブラウザによっては、この機能は正常に使用できない場合があります。Google Chrome の利用を推奨します。
1. HTML5 版 Web クライアントから、クライアントとサーバーとの間でクリップボードの共有が可能になりました。これにより、サーバー側のワープロソフトやテキストエディタ等と、クライアント側のワープロソフトやテキストエディタ等との間でテキストのコピー＆ペーストが可能になりました。この機能を有効にするには、Web ブラウザにおけるクリップボードの共有機能を有効にする必要があります。Web ブラウザによっては、この機能は正常に使用できない場合があります。Google Chrome の利用を推奨します。

## beta8preview4 - 2021/10/17
1. 中継ゲートウェイの SSL 接続処理パフォーマンスを大幅に向上させました。beta8preview1 では、OpenSSL 3.0 における挙動やアーキテクチャの大規模変更が原因で、性能の劣化が発生していました。beta8preview4 では、コード全体の大幅な見直しを行ない、SSL_CTX の高速キャッシュ機構を実装することにより、この問題を解決しました。
1. Win32 版クライアントアプリが Nuro 光の ZTE 社の HGW の配下の PC で利用できないという問題が報告されました。これは、Nuro 光の ZTE 社の HGW の DNS キャッシュサーバーのバグであることが判明しました。この問題を回避するためのコードを追加しました。
1. Let's Encrypt のルート証明書の有効期限切れ問題 (2021/09/30 に発生) に対応するため、すべての Let's Encrypt 中間証明書チェーンに含まれる証明書をクライアントに対して強制的に Web クライアントに対して送付するようにしました。【背景】 HTML5 版 Web クライアントにおいて、SSL (HTTPS) ネゴシエーション時は、Web サーバーは、Web クライアントに対して、以前のバージョンは、Web サーバーを動作させている OS または OpenSSL が報告する証明書チェーンをそのまま送付していました。しかしながら、2021/09/30 頃に世界的に発生している現象である Let's Encrypt のルート証明書および中間証明書の有効期限切れによるエラー発生等の事象に伴い、OS または OpenSSL が報告する証明書チェーンに Let's Encrypt の有効期限が切れた古い証明書のみが含まれているか、または/および新しい Let's Encrypt のルート証明書に対する中間証明書が含まれていない場合に、新しい Let's Encrypt のルート証明書に対する中間証明書が HTTPS クラアントに送付されないことから、主に Let's Encrypt 証明書を利用する場合において、一部の HTTPS クライアントで証明書検証エラーが発生するようになりました。【解決手法】 この問題を解決するため、HTML5 版 Web クライアント用 Web サーバーは、OS または OpenSSL が報告する証明書チェーンの内容にかかわらず、強制的に、すべての中間証明書チェーンを Web クライアントに送付するようにしました。なお、この挙動は Linux 上でシン・テレワークシステム HTML5 版 Web クライアント用 Web サーバーを稼働させている場合にのみ適用されます。Windows 上でシン・テレワークシステム HTML5 版 Web クライアント用 Web サーバーを稼働させている場合は、単一の SSL 証明書信頼パスのみがクライアントに送付されます。
1. Windows 11 完成版での動作確認を一通り行ないました。Windows 11 におけるすべての機能と共に動作することを検証している訳ではありませんが、一般的な Windows 11 環境において、支障なく動作することを確認しています。


## beta8preview3 - 2021/09/22
1. HTML5 版 Web クライアントにおいて、証明書認証を行なう際に、認証に失敗した場合にその詳細な原因とともにエラーメッセージを表示するようにしました。

## beta8preview1 - 2021/09/19
1. 内部的に使用する暗号ライブラリを OpenSSL 3.0.0 にアップグレードしました。

## beta7fix1 - 2021/08/05
1. IPv6 の DNS 名前解決が有効であるが IPv6 通信ができない環境で、クライアントアプリで RDP 接続エラーが発生する問題を修正しました。

## beta7 - 2021/08/05
1. HTML5 版 Web クライアントに対応しました。HTML5 版 Web クライアントを使用すると、Web ブラウザから職場の「シン・テレワークシステム サーバー」端末に接続し、Windows デスクトップにリモートログインできます。自宅の Mac や ChromeBook などの端末から、職場の Windows を安全・快適に、全画面で操作できます。
1. ポリシー規制サーバーの設定ファイルで、新たに「DENY_CLIENTS_APP」および「DENY_CLIENTS_HTML5」値が設定できるようになりました。DENY_CLIENTS_APP に 1 を設定すると、従来のデスクトップアプリ版のシン・テレワークシステム クライアントからの接続が禁止されます。DENY_CLIENTS_HTML5 に 1 を設定すると、HTML5 版 Web クライアントからの接続が禁止されます。DENY_CLIENTS_APP と DENY_CLIENTS_HTML5 の両方に 1 を設定することはできません。
1. NTT ドコモ等の IPv6 シングルスタック (IPv6 SS) 環境 (NAT64 / DNS64) に対応しました。
1. クライアント側アプリにおいて IPv6 シングルスタック (IPv6 SS) 環境でかつ NAT64 / DNS64 が有効な場合にエラーが発生する問題を解消しました。
1. インストール時に言語を選択することができるようになりました。
1. クライアント側アプリの設定画面で「リモート画面起動時に内部的に 127.0.0.1 を示す特殊な FQDN 名を指定せず 127.0.0.1 を直接指定 (名前解決エラー時に ON にしてみてください)」オプションを追加しました。

## beta7preview16 - 2021/03/27
1. Wake on LAN パケット送信機能において、ターゲットのサーバー側コンピュータが属しているすべてのサブネットのブロードキャストアドレス宛にも WoL パケットを送付するようにしました。これは、組織の LAN がルータまたはレイヤ 3 スイッチで分割されており、かつ、レイヤ 3 スイッチ等において「IP Directed Broadcast」機能が有効な場合に効果的です。IP Directed Broadcast 機能が有効な場合、異なるレイヤ 3 セグメント上のサーバーを WoL で起動することが可能な場合があります。レイヤ 3 スイッチの側の設定が必要です。例として、Cisco 社のドキュメントは以下のとおりです: https://www.cisco.com/c/ja_jp/support/docs/switches/catalyst-3750-series-switches/91672-catl3-wol-vlans.html 一般的に、他のスイッチ製品にも同様の機能があります。この機能を利用するには、「ターゲット PC」および「トリガ PC」の両方を、少なくとも beta7preview16 以降にアップデートする必要があります。
1. LGWAN 版において、クライアントプログラムの設定画面で "接続先のサーバーが「行政情報システム適合モード」の場合、「完全閉域化ファイアウォール」を起動" が OFF になっている場合でも、「完全閉域化ファイアウォール」が起動してしまう問題を修正しました。
1. サーバーのサイレントアンインストール機能において、設定ファイルの自動削除に対応しました。「"C:\Program Files\Local Governments Telework System for LGWAN Server\LgwanThinSetup.exe" /auto:1 /deleteconfig:1」 (パスはインストールされた環境によって異なる場合があります) を実行すると、アンインストールが無操作で完了し、設定ファイルも自動消去されます。これにより、サーバーにおけるインストール後のユーザーの設定情報 (OTP のメールアドレス、MAC アドレス等) は消去されます。その後再度サーバーをインストールすると、これらの再設定が必要になります。ただし、サーバーの固有 ID と、これに紐付けられているコンピュータ ID は変化しません。固有 ID をリセットしたい場合は、別途リセット操作が必要です。

## beta7preview15 - 2021/03/04
1. ハイパースケール版のコントローラのコードが .NET SDK 5.0.200 でコンパイルできなくなっていた問題を修正しました。これは、おそらく Microsoft の側の C# コンパイラのバグです。

## beta7preview14 - 2021/01/29
1. LGWAN 版では、サーバープログラムが、初期状態で中継システムにセッションを確立しないようにしました。プロキシサーバーの設定画面を開いて設定を行なうまで、セッションは未確立の状態となります。(プロキシサーバーを使用しない場合も、一度プロキシサーバーの設定画面を開く必要があります。)
1. サイレントアンインストールに対応しました。「"C:\Program Files\Local Governments Telework System for LGWAN Server\LgwanThinSetup.exe" /auto:1」 (パスはインストールされた環境によって異なる場合があります) を実行すると、アンインストールが無操作で完了します。(通常はありませんが、万一アンインストール中にエラーが発生した場合は、エラーメッセージで停止します。) 
1. LGWAN 版では、これまで、完全閉域化ファイアウォールを無効にするオプションが設定されている場合でも、完全閉域化ファイアウォールが起動してしまっていました。この度、ポリシー規制サーバーで完全閉域化ファイアウォールを強制できるようにしましたので、完全閉域化ファイアウォールが強制の場合は必ず同機能が起動し、それ以外の場合は、完全閉域化ファイアウォールを無効にするオプションが設定されている場合は完全閉域化ファイアウォールが起動しないようにしました。


## beta7preview13 - 2021/01/29
1. インストーラで、Windows のグループポリシーでリモート接続が未構成の場合でも誤って「Windows のグループポリシーでリモート接続が禁止されています。」という注意メッセージが表示されてしまう問題を解決しました。ポリシーが「未構成」の場合を「有効」として誤って取り扱っていたことが原因でした。「未構成」の場合は「無効」として取り扱うように修正しました。

## beta7preview12 - 2021/01/26
1. beta7preview9 で追加された、サーバー側メモリ容量が 4GB 以下または空きメモリが 512MB 未満の場合に表示される画面には、一般的なメモリ増設の効用を啓発するメッセージが含まれています。このメッセージは、IPA においてバイナリをビルドする形態で配布する、シン・テレワークシステムのパブリック版で表示されることを目的としたものであり、コンピュータにメモリを増設することにより「生産性の向上、残業削減、余暇の増加、消費電力の削減、幸福度の増加および所得の増大」等が実現されることを IPA サイバー技術研究室より呼び掛けるメッセージです。しかしながら、プライベート版は各利用企業等が自らソースコードをビルドしてバイナリを生成し、各社社員に配布することを目的としているものであり、各利用企業の方針と IPA によるメモリ増設の効用の呼び掛けの内容が矛盾し、混乱が生じる場合があります。各利用企業等では、メモリ増設の効用を自社社員に知らせたくない場合もあります。そこで、前記の一般的なメモリ増設の効用のメッセージはパブリック版でのみ表示されるようにし、プライベート版では表示されないようにしました。なお、プライベート版でメモリ増設の効用の呼び掛けメッセージを復活したい場合は、プライベート版ソースコードの「IPA-DN-ThinApps-Private\src\bin\hamcore\strtable_ja.patch.stb」ファイルの「DS_MEMORY_MSG_1」および「DS_MEMORY_MSG_2」の行を削除してください。


## beta7preview11 - 2021/01/26
1. beta7preview10 で追加されたポリシー規制サーバーの設定項目の「REQUIRE_MINIMUM_CLIENT_BUILD」が、誤って「REQUIRE_MIMIMUM_CLIENT_BUILD」というスペルとなっており、正しく設定項目の読み込みができませんでした。スペルミスを修正しました。正しくは、「REQUIRE_MINIMUM_CLIENT_BUILD」です。
1. beta7preview9 で追加されたアカウントロックアウト機能について、動作を改良しました。ロックアウトが発生していない状態で何度かユーザー認証に失敗し (依然としてロックアウトしきい値未満の失敗の状態で)、その後、ユーザー認証に 1 度成功した場合は、ロックアウトのカウントダウンをクリアするようにしました。また、ユーザー認証に失敗したことが契機となってアカウントロックアウトが発生した場合は、ロックアウトが発生した旨のエラーメッセージを返すようにしました。
1. MAC アドレス認証が有効にされている場合、通常、サーバー設定ツールを終了する際に MAC アドレスが 1 つもローカル設定で登録されていない場合に、設定を促すメッセージボックスが表示されます。しかしながら、ポリシー設定ファイルで「SERVER_ALLOWED_MAC_LIST_URL」項目が設定されている場合、MAC アドレス一覧はポリシー規制サーバー側で管理することが可能になります。そこで、「SERVER_ALLOWED_MAC_LIST_URL」項目が設定されている場合は、上記の設定を促すメッセージボックスを表示しないようにしました。なお、ポリシー設定ファイルに「SERVER_ALLOWED_MAC_LIST_URL」項目が設定されているものの、その URL が誤っていたり、MAC アドレスを記述したテキストファイルの記載が誤っていたりしている場合でも、メッセージの表示は省略されるようになります。ポリシーファイルの「SERVER_ALLOWED_MAC_LIST_URL」項目を記載される際は、十分ご注意ください。
1. サーバーおよびクライアントアプリのプロキシ設定画面に、「中継システムへの接続を無効化する」オプションを追加しました。このオプションを有効にすると、中継システムへの通信が発生しなくなります。すでにサーバーから中継システムへのセッションが確立されている場合は、セッションは切断されます。
1. インストーラのビルドにおいて、クライアントアプリのみを含んだインストーラをビルドすることができるようになった。ソースコード中の「src/Vars/VarsActivePatch.h」の「ThinSetupClientOnly」項目を「true」に変更することにより、クライアントアプリのみを含むインストーラが作成される。「クライアントアプリとサーバーアプリの両方を含むインストーラ」と、「クライアントのみを含むインストーラ」の 2 種類をビルドしたい場合は、同ヘッダファイルを書換えて、2 回ビルドすること。(これは、少し手抜きの実装であるが、本機能の需要はそれほど多くないため、ご容赦いただきたい。) なお、「ThinSetupServerOnly」 と 「ThinSetupClientOnly」 はいずれか一方しか指定できなません。「ThinSetupClientOnly」と「ThinSetupServerOnly」の両方を true にすると、全く意味のないインストーラが作成されますので、ご注意ください。

## beta7preview10 - 2021/01/25
1. ポリシー規制サーバーの設定項目に「ENFORCE_LIMITED_FIREWALL_COMPUTERNAME_STARTWITH」を追加しました。この設定は、「ENFORCE_LIMITED_FIREWALL」設定機能 (「完全閉域化ファイアウォール」機能を強制的に有効にする機能) を有効にしたいけれども、一部の端末については無効にしたい (除外したい) というような場合に利用できます。この項目として設定されている文字列が、接続しようとしているクライアント側の Windows コンピュータの「コンピュータ名」の文字列の先頭部分に一致した場合は、当該クライアントからの接続に際しては、「ENFORCE_LIMITED_FIREWALL」が 0 であるとみなして接続処理がされます。この項目には、スペース、カンマまたはセミコロン区切りで、複数の文字列を指定できます。複数の文字列を指定した場合、いずれか 1 つと一致した場合は有効であるとみなされます。大文字・小文字は区別されません。この項目は、「ENFORCE_LIMITED_FIREWALL」設定項目が 1 に設定されている場合にのみ有効です。この機能は、シン・テレワークシステムのパブリック版では利用できません。
1. シン・テレワークシステム サーバーの自動インストーラ (無人インストーラ) (「/auto:1」というコマンドラインオプションを指定することで利用可能) において、追加で「/NOAFTERRUN:1」というコマンドラインオプションにも対応しました。「/NOAFTERRUN:1」を設定すると、インストーラ完了後に「サーバー設定ツール」が自動的に起動しないようになります。
1. (LGWAN 版のみ) サーバーの自動インストーラ (無人インストーラ) を利用中に、LGWAN 版のネットワーク自動検出後に次の画面に自動的に進まない問題を解決した。
1. ポリシー規制サーバーの設定項目に「REQUIRE_MINIMUM_CLIENT_BUILD」を追加しました。この項目には整数値を指定できます。この項目が指定されている場合は、サーバーに接続しようとしてきたクライアントのビルド番号が、指定された番号未満の場合に、クライアント側に対してバージョンアップを促すエラーメッセージが表示され、接続が拒否されます。この機能は、古いバージョンのクライアントからの接続を拒否したい場合に利用できます。たとえば、古いバージョンのクライアントにはあるセキュリティ機能が存在しない場合、そのような古いクライアントの接続を禁止することができます。「REQUIRE_MINIMUM_CLIENT_BUILD」の値は、サーバー側のソフトウェア自身のビルド番号以下でなければなりません。(サーバー側のソフトウェアのビルド番号を超える値が設定されている場合は、サーバー側のソフトウェアのビルド番号が設定されているとみなされます。) この機能は、シン・テレワークシステムのパブリック版では利用できません。この機能は、クライアントからのプロトコル上の自己申告値を信用して動作します。クライアントが不正に改造されている場合で、実際と異なるビルド番号をクライアントが主張する場合は、サーバーはこれを見分けることができませんので、ご注意ください。本機能はあくまでも一般的なユーザーによる古いバージョンによる接続を規制するものであり、高度なユーザーによる古いバージョンのクライアントからの接続をすべて遮断できるものではありません。

## beta7preview9 - 2021/01/24
1. シン・テレワークシステム サーバーの自動インストーラ (無人インストーラ) に対応した。大量のコンピュータへのサーバーのインストールが快適になる。インストーラの EXE ファイルを実行する際に「/auto:1」というコマンドラインオプションを指定することにより、インストーラはデフォルトのオプションのまま、無人で最後まで進み、サーバー設定ツールが自動的に起動するところまで進むようになる。なお、このコマンドラインオプションを指定して実行する際には、Administrators 権限が必要である。権限がない場合は、UAC ポップアップが表示される。また、インストール中にデフォルトで次に進むことができないようなエラーが発生した場合は、当該エラーの表示部分で停止するので、それ以降は手動でインストールをする必要がある。
1. プライベート版で完全閉域化ファイアウォール機能に対応した。アプリケーションビルド時において、ソースコード中の「src/Vars/VarsActivePatch.h」の「ThinFwMode」項目を「true」に変更することにより、「完全閉域化ファイアウォール」機能がクライアント接続時に呼び出されるようになる。「完全閉域化ファイアウォール」において通信を例外的に許可する通信先 IP アドレス (IP サブネット) のリストは、インストーラのビルド時に予め「src/bin/hamcore/WhiteListRules.txt」に列挙しておく必要がある。クライアント側も新しいバージョンが必要である。
1. アプリのインストーラビルド時のソースコード中の「src/Vars/VarsActivePatch.h」の「ThinFwMode」項目が「false」の場合であっても、ポリシー規制サーバーで「ENFORCE_LIMITED_FIREWALL」項目を「1」に設定することにより、「完全閉域化ファイアウォール」機能を強制的に有効にすることができるようにした。クライアント側も新しいバージョンが必要である。プライベート版と LGWAN 版では利用できるが、パブリック版では利用できない。
1. サーバー側で「tunnel_log」ディレクトリにサーバーと中継システムとの間の通信の詳細なログを出力するようにした。サーバーと中継システムとの間が頻繁に切れるような場合は、このログを確認することにより、原因を特定することが容易となる。
1. インストーラのビルドにおいて、サーバーアプリのみを含んだインストーラをビルドすることができるようになった。ソースコード中の「src/Vars/VarsActivePatch.h」の「ThinSetupServerOnly」項目を「true」に変更することにより、サーバーアプリのみを含むインストーラが作成される。「クライアントアプリとサーバーアプリの両方を含むインストーラ」と、「サーバーアプリのみを含むインストーラ」の 2 種類をビルドしたい場合は、同ヘッダファイルを書換えて、2 回ビルドすること。(これは、少し手抜きの実装であるが、本機能の需要はそれほど多くないため、ご容赦いただきたい。)
1. 「MAC アドレス認証における MAC アドレスのリストを、ポリシー規制サーバー側で一元管理し、ユーザーに自由に管理させたくない」という要望に対応するため、ポリシー規制サーバーの設定ファイルに「NO_LOCAL_MAC_ADDRESS_LIST」を追加した。これを「1」に設定することにより、ユーザーは MAC アドレス認証における MAC アドレスのリストを手動で設定することができなくなる。なお、「NO_LOCAL_MAC_ADDRESS_LIST」が有効となるためには、ポリシー設定ファイルの「CLIENT_ALLOWED_MAC_LIST_URL」および「ENFORCE_MACCHECK」が設定されている必要がある。
1. LGWAN 版において、クライアントが Administrators または SYSTEM 権限で動作している場合は、ユーザーが指定した mstsc.exe ファイルを実行することができないようにした。
1. OTP において、SMTP (メール) の代わりに AWS SNS (Amazon Simple Notification Service) を用いた SMS 送信に対応した。(ハイパースケール版のみ。) 詳細は、ハイパースケール版のドキュメントの 8-19 節「OTP を電子メールの代わりに SMS で送信する方法」を参照すること。
1. インストーラの EXE ファイルと同じディレクトリに EntryPoint.dat ファイル (テキストファイル) が設置されている場合は、このファイルが、インストーラビルド時に埋め込まれる EntryPoint.dat ファイルに優先して、サーバーと共にインストールされるようにした。これは、たとえばシン・テレワークシステム中継システムを組み込んだアプライアンスを実装したとき、HTML 管理画面等から、その中継システムに接続できるインストーラの ZIP ファイルをダウンロードできるような機能を実装する際に、大変便利である。EXE ファイルそのものはすべてのシステムで共通にしておき、EntryPoint.dat ファイルのみ、システム毎に異なるファイルを自動生成して ZIP でダウンロード可能とするシステムを、容易に構築できるようになった。このことにより、ユーザーはインストーラを独自にビルドする必要がなく、当該アプライアンスの製造元が 1 回のみビルドすればよい。そして、このことは Microsoft Authenticode 署名をインストーラにアプライアンス出荷元があらかじめ付与することができることも意味するのである。
1. クライアント証明書認証における OCSP (Online Certificate Status Protocol) 検証の実装。ポリシー規制サーバーの「ENABLE_OCSP」項目を「1」に設定することにより、サーバーは、クライアント証明書認証要求があった場合で、かつ認証がサーバーにあらかじめ登録されている信頼された証明書 (CA 等) による署名の検証によって実施される場合に、当該クライアント証明書の拡張フィールドに OCSP サーバーの URL が記載されている場合は、その OCSP サーバーの URL 宛に OCSP プロトコルにより証明書が有効かどうかの検証を試みます。無効であると回答された場合は、ログファイルにその旨を記載し、証明書認証は失敗します。OCSP サーバーとの通信に失敗した場合は、検証は成功したものとみなされます。
1. アカウントロックアウト機能の実装。ポリシー規制サーバーの「AUTH_LOCKOUT_COUNT」および「AUTH_LOCKOUT_TIMEOUT」項目を 1 以上の整数に設定することにより、ユーザー認証 (パスワード認証) においてパスワードを誤った場合のアカウントロックアウトが可能となりました。AUTH_LOCKOUT_COUNT には、ロックアウトが発生するまでの認証失敗回数を指定します。AUTH_LOCKOUT_TIMEOUT には、ロックアウトが自動解除されるまでのタイムアウト値を秒単位で指定します。
1. 無操作時のタイムアウト実装。ポリシー規制サーバーの「IDLE_TIMEOUT」項目を 300 以上の整数に設定することにより、ユーザーがクライアント側でマウスを「IDLE_TIMEOUT」で指定された秒数以上無操作であった場合は、クライアント側の接続が切断され、無操作タイムアウトが発生した旨のメッセージボックスがクライアント側の画面に表示されるようになります。この機能が有効となるには、クライアント側のバージョンも beta7preview9 以降である必要があります。それ以前のクライアントの場合は、無視されます。
1. ポリシー規制サーバーの「SERVER_ALLOWED_MAC_LIST_URL」による MAC アドレス一覧テキストファイルの指定において、MAC アドレス一覧テキストファイルの先頭行に UTF-8 の BOM 文字が入っていた場合、その BOM 文字を除外して処理を行なうように改良しました。
1. 空きメモリ容量が十分でない場合、「サーバー設定ツール」で警告メッセージが表示されるようにしました。


## beta7preview8 - 2021/01/12
1. プライベート版 (ハイパースケール版) を実装しました。
1. コントローラの完全冗長に対応しました。
1. サーバー版で詳細デバッグログを保存する機能を実装しました。
1. (LGWAN 版のみ) インストール時に RDP がポリシーで無効になっている場合は、クリップボードおよびファイル共有をインストール時に無効化し、その代わり、毎回の接続時にはポリシーをいじらないようにした。また、インストール時に RDP がポリシーで無効になっている場合は、その旨のメッセージを表示するようにした。
1. サーバー側ソフトウェアにおいて、Windows のローカルグループポリシーまたはドメイングループポリシーでリモートデスクトップが無効である場合でも接続受付時に強制的に有効にするようにしました。


## beta7preview6 - 2020/12/05
1. クライアント接続中はクライアント側 PC のシステムがスリープしないようにしました。
1. 統計機能を実装しました。


## beta7preview1-5 - 2020/11/30
1. プライベート版 (スタンドアロン版) を実装しました。
1. Windows において Admin 権限を有しているかどうかの判定を厳密化しました。
1. (LGWAN 版のみ) クリップボード履歴の保存を禁止しました。Windows 標準のスクリーンショットホットキーによるスクリーンショット撮影を禁止しました。
1. サーバーでリモートアクセス中におけるプロセスの起動 / 終了のログを保存できるようにしました。
1. ゲートウェイで DisableDoSProtection オプションを実装しました。
1. LGWAN 版を実装しました。
1. ポリシーで OTP、MAC アドレス検査、クライアント検疫検査、透かし を強制的に無効化できるようにしました。
1. MAC アドレスリストがマルチスレッド競合によって稀に消えてしまう問題を解決しました。
1. 完全閉域 FW をオプションで OFF にもできるようにしました。
1. 登録キーに対応しました。
1. Proxy Protocol に対応しました。
1. Windows 10 2004 クリーンインストール環境で「Windows Hello 認証」が強制されている場合は、RDP 接続ができない問題があるため、強制を解除するようにしました。
1. ソースコードをサブモジュールに分離し、アクティブパッチやブランディングを可能にしました。
1. Visual Studio 2019 によるビルドに対応しました。
1. WhiteList Rules でプライベート IP の範囲が間違っていたのを修正しました。
1. 行政モードでサーバー側が検疫 ON の場合は、必ず FW 機能を強制するようにしました。


## beta6 - 2020/07/09
1. Wake on LAN 機能 (接続先端末の電源を自宅から ON する機能)
1. 画面撮影・キャプチャ防止のための電子透かし機能
1. 固有 ID 初期化機能 (VDI クローン対応)
1. クライアント MAC アドレス認証のポリシーサーバーによるリスト一元管理機能
1. 完全閉域化 FW 機能 (リモート利用中はユーザー自宅 PC とインターネットとの間を完全に遮断)
1. ポリシーサーバーによるサーバー端末の明示的着信許可機能 (リストに登録されていないサーバー端末は動作禁止する)


## beta5 - 2020/05/14
1. 二要素認証・ワンタイムパスワード (OTP) 機能
1. マイナンバーカードを用いたユーザー認証機能
1. クライアント検疫機能・MAC アドレス認証機能
1. エンタープライズ環境用ポリシー規制サーバー機能
1. 行政情報システム適応モード (中継システムの IP 範囲の限定)


## beta4 - 2020/04/30
1. 「ワンタイムパスワード認証 (OTP)」 を追加しました。企業環境での既存のセキュリティポリシーに準拠するため、「二要素認証に対応してほしい」、「OTP に対応してほしい」というご要望にお応えして、新規開発をいたしました。


## beta3 - 2020/04/27
1. 「仮想マルチディスプレイ機能」を追加しました。「職場の PC」にディスプレイが 1 枚しかない場合でも、自宅の PC にディスプレイが 2 枚以上あれば、自宅から職場の PC をリモート操作する際にマルチディスプレイ化して、大変快適に操作することができます。
1. 「パスワード複雑性を満たしていなくても、警告を無視すれば簡単なパスワードを設定できるのは良くないのではないか。」というご意見をいただきましたので、パスワード複雑性を満たしていないパスワードを設定することをできなくしました。(Beta 2 までは警告メッセージは無視可能でしたが、Beta 3 では、無視可能な警告メッセージは廃止され、無視することができないエラーメッセージとなりました。)
1. パスワード複雑性の規則を見直し、(1) 8 文字以上で、小文字・大文字・数字・記号のうち少なくとも 3 種類以上が使用されている。(2) 16 文字以上で、小文字・大文字・数字・記号のうち少なくとも 2 種類以上が使用されている。(3) 24 文字以上である。のいずれかを満たしていれば可としました。
1. 「シン・テレワークシステム サーバー」および「シン・テレワークシステム クライアント」と、中継システムとの間の通信のセキュリティ (可用性) を向上しました。中継システムにおけるロードバランサとの間の通信が、何らかの通信障害により確立できない場合は、セカンダリロードバランサに対して接続を試みるようになりました。また、セカンダリロードバランサを、複数のドメインおよび AS に分散して配置しました。これにより、通信経路に障害があり 1 つのロードバランサと通信ができない場合でも、他のロードバランサに迂回して通信が確立できるようになりました。
1. 「シン・テレワークシステム クライアント」の起動時に、より新しいバージョンが利用可能になっている場合は画面に案内を表示するようにしました。この機能は、「バージョン情報」画面から無効にできます。

## beta2 - 2020/04/24
1. 「高度なユーザー認証」機能の証明書認証で、X.509 証明書のビット数が 1024 bit より大きい場合に認証に失敗する問題を解決しました。
1. HTTP プロキシサーバーを経由する場合の User Agent の文字列をユーザーが自由に変更できるようにしました。
1. グループポリシーで RDP が無効となっている場合でも、RDP を用いたシステムモードでの接続ができるようにしました。
1. ユーザーのコンピュータのハードディスクが予め攻撃者により別の手段により侵害され、マルウェアのファイルが保存されている場合で、ユーザーが、当該マルウェアと同じディレクトリに本プログラムのインストーラを置いて実行すると、マルウェアも実行されてしまう場合があるセキュリティ問題を解決しました。これはいわゆる DLL プリロード問題と呼ばれる Windows の設計上の脆弱性がもとで発生する問題です。アプリケーション側での対策を施しました。日下部司氏からの報告によるものです。ありがとうございました。
1. クライアントに「リラックス・モード」を追加しました。テレワークの開始前に、リラックスすることができます。デフォルトで無効になっていますが、クライアントのオプション設定から有効にできます。ぜひ、有効にしてみてください。

## beta1 - 2020/04/21
最初のバージョンです。

