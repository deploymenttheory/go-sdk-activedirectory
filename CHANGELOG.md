# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/deploymenttheory/go-sdk-activedirectory/compare/v0.1.0...v0.2.0) (2026-11-19)


### Features

* implement portable LDAP sessions with owned protocol sources ([#187](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/187)) ([678c655](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/678c6553f799e1f2ffdb533af694a70a75d0e4cb))
* **sdk:** add portable security descriptors and guarded ACL adapters ([#192](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/192)) ([71caf55](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/71caf55d7fcb563458a5a1139a03df22dec6cd97))
* **sdk:** expose portable backend and authentication contracts ([#180](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/180)) ([82ebf24](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/82ebf24f413f99a6c19afbb691170b2807c82c05))
* **sdk:** implement portable authenticated replication diagnostics ([#204](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/204)) ([09f3214](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/09f321444f0d40baeb55106f85457fb41e607fc8))
* **sdk:** implement portable conditional expressions and policy validation ([#197](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/197)) ([d0d18b0](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/d0d18b0438c25d91973d2f0adf3bdb2fa36ad4ae))
* **sdk:** implement portable Kerberos authentication and TLS channel binding ([#189](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/189)) ([ea76b4c](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ea76b4c6fa6036c0b4b596994c6bf56d9e33bb29))
* **sdk:** implement portable move delegation ([#207](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/207)) ([4ad1abb](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/4ad1abbe7cfc8a47382dff4196b90d80a6831573))
* **sdk:** preserve portable write and reconciliation contracts ([#202](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/202)) ([137c68d](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/137c68dea857e6d21837acc86630e419228f0add))
* **sdk:** qualify verified LDAPS and StartTLS ([#188](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/188)) ([05e22c9](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/05e22c953ea66f8e2ff384f4bbb88b8ac9929725))
* **sdk:** validate portable domain controller discovery ([#206](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/206)) ([4022967](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/4022967311b983ffb27f9cb59fedd100a3aca4b9))


### Bug Fixes

* **ci:** run module lint with the current Go toolchain ([#186](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/186)) ([e297dbe](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/e297dbe5e701a267183f8476cacfa59a745a73dd))
* distinguish directory capability errors from backend absence ([#178](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/178)) ([15ea352](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/15ea352262bd636178fa3de05cc73158ff29d2ee))
* **lab:** avoid blocking Linux control timeout cleanup ([#196](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/196)) ([8ed0443](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/8ed044395d237e53d1718a9561deaada6b94b83f))
* **lab:** support pre-staged public SASL peers ([#199](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/199)) ([43088a4](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/43088a4ad6a04a26de1380192709d3c5ea91a374))
* **sdk:** mirror PowerShell permission update semantics ([#214](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/214)) ([b217c5d](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b217c5d7b405b9d04d88d665f0b1d5f3479c5427))

## 0.1.0 (2026-11-18)


### Features

* **accounts:** change and reset passwords over verified protected sessions ([#96](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/96)) ([4c96c02](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/4c96c027452be13f435b8067e322da10e1d06f6f))
* **accounts:** honor configured default creation containers ([#105](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/105)) ([02263bd](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/02263bd736eeff8a30e31f41cd467429bd445f03))
* **accounts:** install and uninstall managed accounts on the local host ([#123](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/123)) ([fa26a54](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/fa26a545fa67c1183647f4a7cd4fbcc77080ac08))
* **accounts:** manage stored flags and unlock accounts ([#99](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/99)) ([848e338](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/848e338be2074ac9c921599014ab93deaceef552))
* **accounts:** migrate delegated managed service accounts ([#126](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/126)) ([9399893](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/9399893c08d6b1dd94d2fe1a93c4e696cf516f63))
* **accounts:** read and set password-change permissions ([#104](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/104)) ([c981521](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/c98152196bfbbaff8fe8dcf7a34371ab3500a451))
* **accounts:** reset the host-held managed account credential ([#125](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/125)) ([59390d4](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/59390d4f601c1cfb8499c710113c07714da24b2c))
* **ad:** add cmdlet coverage contract and native SDDL API ([#58](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/58)) ([f03fe9e](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f03fe9edf679a53b859240b68a1e83ba11ad78a8))
* add account expiration and state searches ([#106](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/106)) ([3b094fd](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/3b094fdd44c768cb5ecf0d0a721213604656c4e9))
* add fine-grained password policy operations ([#107](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/107)) ([9597195](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/959719577d1597e6f0374c23cd9b85f5c4734135))
* add principal memberships and authorization groups ([#108](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/108)) ([045e282](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/045e282150e66edc3d1ebbeaacbdd506c0a044e9))
* add RODC password replication policy operations ([#109](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/109)) ([b4bc57a](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b4bc57af16c1bae7f29ffbbd4a7958874a825967))
* add typed LDAP filter composition ([#94](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/94)) ([b6644aa](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b6644aa9f87e05578d1e7dea1391a5cdaab80d2b))
* **auth:** marshal and erase explicit Negotiate credentials ([a16749a](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/a16749a8302176ee3302a0694947e04292a90149))
* **auth:** support explicit Negotiate credentials ([a7bb78d](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/a7bb78d5174a8e056db86fcb227bbc2358b9e325))
* **claims:** add claim type lifecycle with schema-settled value types ([#120](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/120)) ([b3f0bdc](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b3f0bdc74e7157c8e9d4dcba07ba30754377a0de))
* **claims:** manage claim transformation policies and trust links ([#121](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/121)) ([f1b8312](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f1b83128fc44f4c8402a4a30938245480f930c00))
* **client:** connect with current identity and read typed RootDSE ([#66](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/66)) ([f20e0f6](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f20e0f6e9292cfd136f29389e5e42832a8440f8e))
* **computers:** add typed lifecycle and conditional account updates ([#103](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/103)) ([42919ea](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/42919ea122f2cacfdc077d6130c90bb0bd1755f2))
* **coverage:** complete behavioral scenario validation ([#62](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/62)) ([e152a13](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/e152a13d1f8a304bcc1acb94b378379d2e2fb2f2))
* **dccloning:** add native exclusion inventory and inclusion XML ([#75](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/75)) ([025b7f2](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/025b7f29670c683abfdedff307ad273d4eaf9605))
* **dccloning:** prepare native clone configuration ([#81](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/81)) ([1f9d4b1](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/1f9d4b1615227b541911e03bcd1a82453eff092f))
* **directory:** create update rename and delete generic objects ([#95](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/95)) ([afc950b](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/afc950be0772c4cc476eb2012e794e997aab5155))
* **directory:** report the directory's own name for a created object ([#158](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/158)) ([e360832](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/e360832dce6a3b21138b4de8186aca0fe614ed7b))
* **directory:** resolve identities and expose typed attribute values ([#93](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/93)) ([b9b0275](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b9b0275f9dcfd47b54ff10d9292ffa70a9d6270c))
* **directory:** transfer and explicitly seize operation-master roles ([#89](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/89)) ([16fa0d5](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/16fa0d5604a92e9a6c851afd9c7ed8e078f55c75))
* **discovery:** add directory projections and reference qualification ([#73](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/73)) ([6ed975b](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/6ed975bd9dd2c34fb17cbf4aa66cc565dbb0680d))
* **errors:** classify every sentinel into the decisions a caller makes ([#141](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/141)) ([f262bdd](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f262bddaf22d6956a535616d3b56469fdcc041d2)), closes [#138](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/138)
* **groups:** add typed group lifecycle and conditional type updates ([#97](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/97)) ([c9be3e3](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/c9be3e3ede7219ac32e6400aec6a778354308679))
* **groups:** manage direct members and retrieve complete link ranges ([#101](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/101)) ([46a79ea](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/46a79ea51928d79182269f37e31ded4e5df4bfc3))
* **identity:** make an identity survive being written down ([#142](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/142)) ([6ccdabb](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/6ccdabba3f2e43ef815831792ebf6d4bb10a4c80)), closes [#139](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/139)
* **lab:** add isolated Server 2025 reference harness ([#60](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/60)) ([5d89b03](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/5d89b03e1c76bfefcee0e7e0fd66bcf70d8a0830))
* **lab:** capture and assess dMSA migration evidence ([#74](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/74)) ([293da82](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/293da8227810f87d13be8a0a182d9741d24520cb))
* **lab:** download media and provision a rebuildable base lab ([#71](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/71)) ([ffee945](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ffee945f5bd259a86d59c32d1c37622958fc2be3))
* **ldap:** add TLS transports and AD LDS partition support ([#69](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/69)) ([b4093a1](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b4093a1ab840bfba3e3beb217a0caf5ea5e04cf9))
* manage authentication policies and direct account assignments ([#115](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/115)) ([5aa6877](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/5aa6877219ee174797a79114dc9175135be3e2ac))
* manage authentication silos grants and account assignments ([#118](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/118)) ([6791d59](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/6791d59f56ca3d9550ac4461c71cb59ff1505123))
* manage central access rules policies and memberships ([#117](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/117)) ([3f5cce9](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/3f5cce98f3e9e10fb3b04baee4ea7ebd913de3b3))
* manage domain and forest settings and functional levels ([#112](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/112)) ([72d3dd4](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/72d3dd4e2a68d41958bd84e7cbd6d3e16f1f006e))
* manage replication connections site links and bridges ([#114](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/114)) ([b404047](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b40404752ef8abfba6418fd9d2ad4559929ee5de))
* manage replication sites subnets and server moves ([#111](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/111)) ([4788446](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/47884462dd20d8fa4eae4a9b946dc70df922d71e))
* manage service accounts and computer associations ([#116](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/116)) ([6c2f0d5](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/6c2f0d5a1c166df3710bb9587215a5f8153d562c))
* move objects within partitions and across domains ([#113](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/113)) ([b14bd9e](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/b14bd9e89653b373c79068b0605e9d42549754ce))
* **ous:** add lifecycle and accidental-deletion protection ([#100](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/100)) ([cd15c3d](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/cd15c3d99481f4b184b25e2c9c01fe45e18625ae))
* **replication:** read partners, failures, and queues ([#85](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/85)) ([c7acfbc](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/c7acfbccf3ae500ae7243d7506e6d43b14a72c53))
* **replication:** synchronize individual directory objects ([#92](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/92)) ([d476463](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/d4764638f7cd5fd95346bfadea404e0ec3985c86))
* **resources:** manage resource properties, lists and value types ([#122](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/122)) ([ffcd825](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ffcd825ed63fb955df1d52af038297ba85015154))
* restore deleted objects and legacy tombstones ([#110](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/110)) ([61d9fd9](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/61d9fd9a3ac71987a4f8bbd7c97e91e0d9308296))
* **search:** compile AD filter expressions with typed variables ([#98](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/98)) ([ba2e38a](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ba2e38a17e368ad612c8d2f6c51b43a543567a28))
* **users:** add typed lifecycle and staged password creation ([#102](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/102)) ([bb65161](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/bb651613e053ca5ec288d0230d270c96d879fb8a))


### Bug Fixes

* **accounts:** scope uninstall verification and add readiness ([#124](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/124)) ([c976fc1](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/c976fc139e60dc8336c7d53b0781e88a3fb93b0b))
* **ci:** compare lint results against fetched main without autofixes ([#162](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/162)) ([35beec1](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/35beec163b732afbd4c1c8001b97bb9a6e17e972))
* **errors:** separate an unprovable write from a contradicted one ([#150](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/150)) ([9d24fa3](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/9d24fa35bf10b3195d0c6d8ee71ce149136328d9)), closes [#144](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/144)
* **lab:** guard owned switch removal and verify Server 2025 rebuild ([#65](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/65)) ([37e040e](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/37e040e989ff5c928e0bab94489beff7fd6e6a29))
* **lab:** preserve aggregated credential errors and AD status codes ([60cf7c3](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/60cf7c352bb3650785dec51fe73d3b655e784381))
* **lab:** report a connection deadline as a timeout, not a cancellation ([#127](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/127)) ([f929d97](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f929d972397bf44412febc0ab988bb236fd0ef9c))
* **ldap:** keep attribute cursors on their owning OS thread ([#83](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/83)) ([90f22fe](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/90f22fe9558f02c93fd9f8a1fb1a9ba306e05d77))
* **ou:** read protection past the object ACEs a real DACL begins with ([#147](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/147)) ([20ba99c](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/20ba99cd4f20f6201d4bdedb93d86f845ef45bc3)), closes [#146](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/146)
* **replication:** report a site change that left part of itself behind ([#143](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/143)) ([0b77cc2](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/0b77cc226b1f69e7e35b96bb884e6c29624326b1))

## [Unreleased]

### Added

- Added xyz [@your_username](https://github.com/your_username)

### Fixed

- Fixed zyx [@your_username](https://github.com/your_username)

## [1.1.0] - 2021-06-23

### Added

- Added x [@your_username](https://github.com/your_username)

### Changed

- Changed y [@your_username](https://github.com/your_username)

## [1.0.0] - 2021-06-20

### Added

- Inititated y [@your_username](https://github.com/your_username)
- Inititated z [@your_username](https://github.com/your_username)
