let ame2eeF = {};
let Base64 = {};
let sLabel;
let i;

import jsSHA from "jssha";
import BigInteger from "jsbn";

((exports) => {
	function nbi() {
		return new BigInteger.BigInteger(null);
	}

	function nbv(t) {
		let r = nbi();
		return r.fromInt(t), r;
	}

	let ame2eea = {
			encryptPin: function (t, r, e, n) {
				n = ame2eea._hashStandard(n);
				let i,
					o = t.split(",", 2),
					a = ame2eea._formatPINMessage(e, r);
				try {
					return (
						(i = amRsa.oaep.encryptAndGenLabel(o[0], o[1], a, n)).split(":", 2),
						i
					);
				} catch (s) {
					throw (
						(ame2eea.log("Exception when encrypting using RSA-OAEP, msg=" + s),
						s)
					);
				}
			},
			encryptChangePin: function (t, r, e, n, i) {
				i = ame2eea._hashStandard(i);
				let o,
					a = t.split(",", 2),
					s = ame2eea._formatResetPINMessage(e, n, r);
				try {
					return (
						(o = amRsa.oaep.encryptAndGenLabel(a[0], a[1], s, i)).split(":", 2),
						o
					);
				} catch (h) {
					throw (
						(ame2eea.log("Exception when encrypting using RSA-OAEP, msg=" + h),
						h)
					);
				}
			},
			encryptPinForAM: function (t, r, e, n, i) {
				let o = ame2eea.encryptPin(r, e, n, i);
				return ame2eea.formatEncryptionResult(t, o, "");
			},
			encryptChangePinForAM: function (t, r, e, n, i, o) {
				let a = ame2eea.encryptPin(r, e, i, o),
					s = ame2eea.encryptChangePin(r, e, n, i, o);
				return ame2eea.formatEncryptionResult(t, a, s);
			},
			_hashStandard: function (t) {
				return void 0 === t || "" == t
					? "SHA-1"
					: "SHA1" == t
					? "SHA-1"
					: "SHA2-224" == t || "SHA224" == t
					? "SHA-224"
					: "SHA2-256" == t || "SHA256" == t
					? "SHA-256"
					: "SHA2-384" == t || "SHA384" == t
					? "SHA-384"
					: "SHA2-512" == t || "SHA512" == t
					? "SHA-512"
					: t;
			},
			_formatPINMessage: function (t, r) {
				let e = [];
				e[0] = 1;
				let n = amUtil.str2bin(t),
					i = ame2eea._createPINBlock(n),
					o = amUtil.hexDecode(r);
				return e.concat(i, o);
			},
			_formatResetPINMessage: function (t, r, e) {
				let n = [];
				n[0] = 2;
				let i = amUtil.str2bin(t),
					o = amUtil.str2bin(r),
					a = ame2eea._createPINBlock(i),
					s = ame2eea._createPINBlock(o),
					h = amUtil.hexDecode(e);
				return n.concat(a, s, h);
			},
			_createPINBlock: function (t) {
				let r = [],
					e = 0;
				(r[0] = 193), e++, (r[1] = 255 & t.length), e++;
				for (let n = 0; n < t.length; n++, e++) r[e] = t[n];
				for (; e % 8; ) (r[e] = 255), e++;
				return r;
			},
			formatEncryptionResult: function (t, r, e) {
				let n = t + "," + r;
				return e.length > 0 && (n = n + "," + e), n;
			},
			log: function (t) {
				try {
					document.testform.debug.value =
						document.testform.debug.value + t + "\n";
				} catch (r) {}
			},
		},
		amHash = {
			encodeSHA1: function (t) {
				return amHash.sha1(t);
			},
			sha1: function (t) {
				const shaObj = new jsSHA("SHA-1", "HEX");
				shaObj.update(amUtil.hexEncode(t));
				return amUtil.hexDecode(shaObj.getHash("HEX"));
				//return amUtil.hexDecode(new jsSHA(amUtil.hexEncode(t),"HEX").getHash("SHA-1", "HEX"))
			},
			sha224: function (t) {
				return amUtil.hexDecode(
					new jsSHA(amUtil.hexEncode(t), "HEX").getHash("SHA-224", "HEX"),
				);
			},
			sha256: function (t) {
				//return amUtil.hexDecode(new jsSHA(amUtil.hexEncode(t),"HEX").getHash("SHA-256", "HEX"))
				const shaObj = new jsSHA("SHA-256", "HEX");
				shaObj.update(amUtil.hexEncode(t));
				return amUtil.hexDecode(shaObj.getHash("HEX"));
			},
			sha384: function (t) {
				return amUtil.hexDecode(
					new jsSHA(amUtil.hexEncode(t), "HEX").getHash("SHA-384", "HEX"),
				);
			},
			sha512: function (t) {
				return amUtil.hexDecode(
					new jsSHA(amUtil.hexEncode(t), "HEX").getHash("SHA-512", "HEX"),
				);
			},
		},
		amRsa = {
			RSAKey: function () {
				(this.n = null),
					(this.e = 0),
					(this.d = null),
					(this.p = null),
					(this.q = null),
					(this.dmp1 = null),
					(this.dmq1 = null),
					(this.coeff = null);
			},
			RSASetPublic: function (t, r) {
				if (!(null != t && null != r && t.length > 0 && r.length > 0))
					throw "Invalid RSA public key";
				(this.n = amUtil.parseBigInt(t, 16)), (this.e = parseInt(r, 16));
			},
			RSADoPublic: function (t) {
				return t.modPowInt(this.e, this.n);
			},
			RSAEncrypt: function (t) {
				if (null == t) return null;
				let r = this.doPublic(t);
				if (null == r) return null;
				let e = r.toString(16);
				return 0 == (1 & e.length) ? e : "0" + e;
			},
		};
	(amRsa.RSAKey.prototype.doPublic = amRsa.RSADoPublic),
		(amRsa.RSAKey.prototype.setPublic = amRsa.RSASetPublic),
		(amRsa.RSAKey.prototype.encrypt = amRsa.RSAEncrypt),
		(amRsa.oaepEncode = function (t, r, e, n) {
			let i, o;
			if ("SHA-1" == n) (i = 20), (o = amHash.sha1);
			else if ("SHA-224" == n) (i = 28), (o = amHash.sha224);
			else if ("SHA-256" == n) (i = 32), (o = amHash.sha256);
			else if ("SHA-384" == n) (i = 48), (o = amHash.sha384);
			else {
				if ("SHA-512" != n)
					throw "OAEP: HASH algorithm is not recognized, hashAlgo=" + n;
				(i = 64), (o = amHash.sha512);
			}
			let a = e.length;
			if (a > t - 2 * i - 2) throw "The message to be encrypted is too long";
			for (var s = [], h = t - a - 2 * i - 2, u = 0; h > u; u++) s[u] = 0;
			let l = o(r),
				f = [];
			f = f.concat(l, s, 1, e);
			let c = amUtil.generateRandom(i);
			let g = amRsa._MGF1(c, t - i - 1, n);

			let p = amUtil.xor(f, g);
			let d = amRsa._MGF1(p, i, n);
			let m = amUtil.xor(c, d);
			return [0].concat(m, p);
		}),
		(amRsa._MGF1 = function (t, r, e) {
			let n,
				i = [],
				o = [],
				a = [],
				s = 0;
			if ("SHA-1" == e) n = amHash.sha1;
			else if ("SHA-224" == e) n = amHash.sha224;
			else if ("SHA-256" == e) n = amHash.sha256;
			else if ("SHA-384" == e) n = amHash.sha384;
			else {
				if ("SHA-512" != e)
					throw "MGF: HASH algorithm is not recognized, hashAlgo=" + e;
				n = amHash.sha512;
			}
			for (let h = 0; r > s; h++) {
				(i[0] = (h >> 24) & 255),
					(i[1] = (h >> 16) & 255),
					(i[2] = (h >> 8) & 255),
					(i[3] = 255 & h),
					(a = n(t.concat(i)));
				for (let u = 0; u < a.length && r > s; u++, s++) o[s] = a[u];
			}
			return o;
		}),
		(amRsa.oaep = {}),
		(amRsa.oaep.encryptAndGenLabel = function (t, r, e, n) {
			let i = new Array(16);
			new amUtil.SecureRandom().nextBytes(i),
				(sLabel = amUtil.hexEncode(i)),
				(sLabel = amUtil.zeroPad(sLabel, 32));
			let o = amRsa.oaep.encrypt(t, r, i, e, n);
			return sLabel + ":" + o;
		}),
		(amRsa.oaep.encrypt = function (t, r, e, n, i) {
			let o = new amRsa.RSAKey();
			o.setPublic(t, r);
			let a = amRsa.oaepEncode(t.length / 2, e, n, i),
				s = o.encrypt(new BigInteger.BigInteger(a));
			return (s = amUtil.zeroPad(s, t.length)).toUpperCase();
		}),
		(amRsa.pkcs1 = {}),
		(amRsa.pkcs1.encrypt = function (t, r, e) {
			let n = new amRsa.RSAKey();
			n.setPublic(t, r);
			let i = amRsa.pkcs1pad2(e, t.length / 2),
				o = n.encrypt(new BigInteger.BigInteger(i));
			return (o = amUtil.zeroPad(o, t.length)).toUpperCase();
		}),
		(amRsa.pkcs1pad2 = function (t, r) {
			if (r < t.length + 11) throw "Message too long for RSA";
			let e = new Array(2);
			(e[0] = 0), (e[1] = 2);
			for (
				let n = r - t.length - 2,
					i = new Array(n),
					o = new amUtil.SecureRandom(),
					a = new Array(),
					s = 0;
				n - 1 > s;
				s++
			) {
				for (a[0] = 0; 0 == a[0]; ) o.nextBytes(a);
				i[s] = a[0];
			}
			return (i[n - 1] = 0), e.concat(i, t);
		});
	let amAes = {
		cipher: function (t, r) {
			for (var e = r.length / 4 - 1, n = [[], [], [], []], i = 0; 16 > i; i++)
				n[i % 4][Math.floor(i / 4)] = t[i];
			n = amAes.addRoundKey(n, r, 0, 4);
			for (var o = 1; e > o; o++)
				(n = amAes.subBytes(n, 4)),
					(n = amAes.shiftRows(n, 4)),
					(n = amAes.mixColumns(n, 4)),
					(n = amAes.addRoundKey(n, r, o, 4));
			(n = amAes.subBytes(n, 4)),
				(n = amAes.shiftRows(n, 4)),
				(n = amAes.addRoundKey(n, r, e, 4));
			var a = new Array(16);
			for (i = 0; 16 > i; i++) a[i] = n[i % 4][Math.floor(i / 4)];
			return a;
		},
		keyExpansion: function (t) {
			for (
				var r = t.length / 4,
					e = r + 6,
					n = new Array(4 * (e + 1)),
					i = new Array(4),
					o = 0;
				r > o;
				o++
			)
				n[o] = [t[4 * o], t[4 * o + 1], t[4 * o + 2], t[4 * o + 3]];
			for (o = r; 4 * (e + 1) > o; o++) {
				n[o] = new Array(4);
				for (var a = 0; 4 > a; a++) i[a] = n[o - 1][a];
				if (o % r == 0)
					for (i = amAes.subWord(amAes.rotWord(i)), a = 0; 4 > a; a++)
						i[a] ^= amAes.rCon[o / r][a];
				else r > 6 && o % r == 4 && (i = amAes.subWord(i));
				for (a = 0; 4 > a; a++) n[o][a] = n[o - r][a] ^ i[a];
			}
			return n;
		},
		subBytes: function (t, r) {
			for (var e = 0; 4 > e; e++)
				for (var n = 0; r > n; n++) t[e][n] = amAes.sBox[t[e][n]];
			return t;
		},
		shiftRows: function (t, r) {
			for (var e = new Array(4), n = 1; 4 > n; n++) {
				for (var i = 0; 4 > i; i++) e[i] = t[n][(i + n) % r];
				for (i = 0; 4 > i; i++) t[n][i] = e[i];
			}
			return t;
		},
		mixColumns: function (t, r) {
			for (var e = 0; 4 > e; e++) {
				for (var n = new Array(4), i = new Array(4), o = 0; 4 > o; o++)
					(n[o] = t[o][e]),
						(i[o] = 128 & t[o][e] ? (t[o][e] << 1) ^ 283 : t[o][e] << 1);
				(t[0][e] = i[0] ^ n[1] ^ i[1] ^ n[2] ^ n[3]),
					(t[1][e] = n[0] ^ i[1] ^ n[2] ^ i[2] ^ n[3]),
					(t[2][e] = n[0] ^ n[1] ^ i[2] ^ n[3] ^ i[3]),
					(t[3][e] = n[0] ^ i[0] ^ n[1] ^ n[2] ^ i[3]);
			}
			return t;
		},
		addRoundKey: function (t, r, e, n) {
			for (var i = 0; 4 > i; i++)
				for (var o = 0; n > o; o++) t[i][o] ^= r[4 * e + o][i];
			return t;
		},
		subWord: function (t) {
			for (var r = 0; 4 > r; r++) t[r] = amAes.sBox[t[r]];
			return t;
		},
		rotWord: function (t) {
			for (var r = t[0], e = 0; 3 > e; e++) t[e] = t[e + 1];
			return (t[3] = r), t;
		},
		sBox: [
			99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
			202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114,
			192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49,
			21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
			9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83,
			209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208,
			239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81,
			163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
			205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
			96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
			224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
			231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
			186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
			112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
			225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40,
			223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187,
			22,
		],
		rCon: [
			[0, 0, 0, 0],
			[1, 0, 0, 0],
			[2, 0, 0, 0],
			[4, 0, 0, 0],
			[8, 0, 0, 0],
			[16, 0, 0, 0],
			[32, 0, 0, 0],
			[64, 0, 0, 0],
			[128, 0, 0, 0],
			[27, 0, 0, 0],
			[54, 0, 0, 0],
		],
		CbcPkcs7: {},
	};
	amAes.CbcPkcs7.encrypt = function (t, r, e) {
		var n = 16,
			i = 8 * r.length;
		if (128 != i && 192 != i && 256 != i) return "";
		for (
			var o = amAes.keyExpansion(r),
				a = amUtil.pkcs7Type1(t, n),
				s = Math.ceil(a.length / n),
				h = new Array(s * n),
				u = e.slice(0),
				l = 0;
			s > l;
			l++
		) {
			for (var f = new Array(n), c = 0; n > c; c++) f[c] = u[c] ^ a[16 * l + c];
			var g = amAes.cipher(f, o);
			for (u = g, c = 0; n > c; c++) h[16 * l + c] = g[c];
		}
		return h;
	};
	var dbits,
		amUtf8 = {
			encode: function (t) {
				return t
					.replace(/[\u0080-\u07ff]/g, function (t) {
						var r = t.charCodeAt(0);
						return String.fromCharCode(192 | (r >> 6), 128 | (63 & r));
					})
					.replace(/[\u0800-\uffff]/g, function (t) {
						var r = t.charCodeAt(0);
						return String.fromCharCode(
							224 | (r >> 12),
							128 | ((r >> 6) & 63),
							128 | (63 & r),
						);
					});
			},
			decode: function (t) {
				return t
					.replace(
						/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,
						function (t) {
							var r =
								((15 & t.charCodeAt(0)) << 12) |
								((63 & t.charCodeAt(1)) << 6) |
								(63 & t.charCodeAt(2));
							return String.fromCharCode(r);
						},
					)
					.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g, function (t) {
						var r = ((31 & t.charCodeAt(0)) << 6) | (63 & t.charCodeAt(1));
						return String.fromCharCode(r);
					});
			},
		},
		canary = 0xdeadbeefcafe,
		j_lm = 15715070 == (16777215 & canary);
	(dbits = 28),
		(BigInteger.BigInteger.DB = dbits),
		(BigInteger.BigInteger.DM = (1 << dbits) - 1),
		(BigInteger.BigInteger.DV = 1 << dbits);
	var BI_FP = 52;
	(BigInteger.BigInteger.FV = Math.pow(2, BI_FP)),
		(BigInteger.BigInteger.F1 = BI_FP - dbits),
		(BigInteger.BigInteger.F2 = 2 * dbits - BI_FP);
	var rr,
		vv,
		BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz",
		BI_RC = new Array();
	for (rr = "0".charCodeAt(0), vv = 0; 9 >= vv; ++vv) BI_RC[rr++] = vv;
	for (rr = "a".charCodeAt(0), vv = 10; 36 > vv; ++vv) BI_RC[rr++] = vv;
	for (rr = "A".charCodeAt(0), vv = 10; 36 > vv; ++vv) BI_RC[rr++] = vv;
	(BigInteger.BigInteger.ZERO = nbv(0)), (BigInteger.BigInteger.ONE = nbv(1));
	var amUtil = {
		byte2dword: function (t) {
			for (var r = new Array(), e = 0; e < t.length; e++)
				r[e >> 2] |= t[e] << (24 - (e % 4) * 8);
			return r;
		},
		dword2byte: function (t) {
			for (var r = new Array(), e = 0; e < 4 * t.length; e++)
				r[e] = (t[e >> 2] >> (24 - (e % 4) * 8)) & 255;
			return r;
		},
		hexDecode: function (t) {
			for (var r = 0, e = 0, n = new Array(1), i = 0; e < t.length; )
				t.charCodeAt(e) != " ".charCodeAt(0)
					? ((i =
							(amUtil.HexToNib(t.charCodeAt(e)) << 4) +
							amUtil.HexToNib(t.charCodeAt(e + 1))),
					  r >= n.length ? n.push(i) : (n[r] = i),
					  ++r,
					  (e += 2))
					: ++e;
			return n;
		},
		HexToNib: function (t) {
			return t >= 65 && 70 >= t
				? t - 55
				: t >= 97 && 102 >= t
				? t - 87
				: t - 48;
		},
		int2bin: function (t, r) {
			for (var e = [], n = r - 1; n >= 0; n--)
				e[r - 1 - n] = (t >>> (8 * n)) & 255;
			return e;
		},
		str2bin: function (t) {
			for (
				var r = [], e = unescape(encodeURIComponent(t)), n = 0;
				n < e.length;
				n++
			)
				r[n] = 255 & e.charCodeAt(n);
			return r;
		},
		bin2str: function (t) {
			for (var r = "", e = 0; e < t.length; e++) r += String.fromCharCode(t[e]);
			return decodeURIComponent(escape(r));
		},
		hex2b64: function (t) {
			return amUtil.base64Encode(amUtil.hexDecode(t));
		},
		hexEncode: function (t) {
			var r = 0,
				e = [];
			for (r = 0; r < t.length; ) (e[r] = amUtil.addHex(t[r])), ++r;
			return e.join("");
		},
		addHex: function (t) {
			var r = (t >>> 4) & 15;
			r += r > 9 ? 55 : 48;
			var e = String.fromCharCode(r);
			return (r = 15 & t), (r += r > 9 ? 55 : 48), e + String.fromCharCode(r);
		},
		pkcs7Type1: function (t, r) {
			var e;
			e = t.length < r ? r - t.length : r - (t.length % r);
			for (var n = [], i = 1; e >= i; i++) n[i - 1] = 255 & e;
			return t.concat(n);
		},
		pkcs7GetPaddingCount: function (t, r) {
			var e = t[t.length - 1];
			if (e > t.length || 0 == e) throw "pad block corrupted";
			for (var n = 1; e >= n; n++)
				if (t[t.length - n] != e) throw "pad block corrupted";
			return e;
		},
		zeroPad: function (t, r) {
			for (var e = t; e.length < r; ) e = "0" + e;
			return e;
		},
		parseBigInt: function (t, r) {
			return new BigInteger.BigInteger(t, r);
		},
		xor: function (t, r) {
			var e = [];
			if (t.length != r.length)
				throw "XOR failure: two binaries have different lengths";
			for (var n = 0; n < t.length; n++) e[n] = t[n] ^ r[n];
			return e;
		},
		generateRandom: function (t) {
			var r = [];
			for (i = 0; i < t; i++) r[i] = Math.floor(256 * Math.random());
			return r;
		},
		base64Encode: function (t) {
			return Base64.encodeByteArray(t);
		},
		Arcfour: function () {
			(this.i = 0), (this.j = 0), (this.S = new Array());
		},
		ARC4init: function (t) {
			var r, e, n;
			for (r = 0; 256 > r; ++r) this.S[r] = r;
			for (e = 0, r = 0; 256 > r; ++r)
				(n = this.S[r]),
					(this.S[r] = this.S[(e = (e + this.S[r] + t[r % t.length]) & 255)]),
					(this.S[e] = n);
			(this.i = 0), (this.j = 0);
		},
		ARC4next: function () {
			var t;
			return (
				(this.i = (this.i + 1) & 255),
				(this.j = (this.j + this.S[this.i]) & 255),
				(t = this.S[this.i]),
				(this.S[this.i] = this.S[this.j]),
				(this.S[this.j] = t),
				this.S[(t + this.S[this.i]) & 255]
			);
		},
	};
	if (
		((amUtil.Arcfour.prototype.init = amUtil.ARC4init),
		(amUtil.Arcfour.prototype.next = amUtil.ARC4next),
		(amUtil.prng_newstate = function () {
			return new amUtil.Arcfour();
		}),
		(amUtil.rng_psize = 256),
		(amUtil.rng_seed_int = function (t) {
			(amUtil.rng_pool[amUtil.rng_pptr++] ^= 255 & t),
				(amUtil.rng_pool[amUtil.rng_pptr++] ^= (t >> 8) & 255),
				(amUtil.rng_pool[amUtil.rng_pptr++] ^= (t >> 16) & 255),
				(amUtil.rng_pool[amUtil.rng_pptr++] ^= (t >> 24) & 255),
				amUtil.rng_pptr >= amUtil.rng_psize &&
					(amUtil.rng_pptr -= amUtil.rng_psize);
		}),
		(amUtil.rng_seed_time = function () {
			amUtil.rng_seed_int(new Date().getTime());
		}),
		null == amUtil.rng_pool)
	) {
		var t;
		amUtil.rng_pool = new Array();
		amUtil.rng_pptr = 0;

		for (; amUtil.rng_pptr < amUtil.rng_psize; )
			(t = Math.floor(65536 * Math.random())),
				(amUtil.rng_pool[amUtil.rng_pptr++] = t >>> 8),
				(amUtil.rng_pool[amUtil.rng_pptr++] = 255 & t);
		(amUtil.rng_pptr = 0), amUtil.rng_seed_time();
	}
	(amUtil.rng_get_byte = function () {
		if (null == amUtil.rng_state) {
			for (
				amUtil.rng_seed_time(),
					amUtil.rng_state = amUtil.prng_newstate(),
					amUtil.rng_state.init(amUtil.rng_pool),
					amUtil.rng_pptr = 0;
				amUtil.rng_pptr < amUtil.rng_pool.length;
				++amUtil.rng_pptr
			)
				amUtil.rng_pool[amUtil.rng_pptr] = 0;
			amUtil.rng_pptr = 0;
		}
		return amUtil.rng_state.next();
	}),
		(amUtil.rng_get_bytes = function (t) {
			var r;
			for (r = 0; r < t.length; ++r) {
				for (var e = amUtil.rng_get_byte(); 0 == r && 0 != (128 & e); )
					e = amUtil.rng_get_byte();
				t[r] = e;
			}
		}),
		(amUtil.SecureRandom = function () {}),
		(amUtil.SecureRandom.prototype.nextBytes = amUtil.rng_get_bytes),
		(amUtil.log = (function (t) {
			try {
				document.testform.debug.value =
					document.testform.debug.value + t + "\n";
			} catch (r) {}
		})(function (t) {
			"use strict";
			function r(t, r) {
				(this.highOrder = t), (this.lowOrder = r);
			}
			function e(t, r) {
				var e,
					n = [],
					i = (1 << r) - 1,
					o = t.length * r;
				for (e = 0; o > e; e += r)
					n[e >>> 5] |= (t.charCodeAt(e / r) & i) << (32 - r - (e % 32));
				return {
					value: n,
					binLen: o,
				};
			}
			function n(t) {
				var r,
					e,
					n = [],
					i = t.length;
				if (0 != i % 2) throw "String of HEX type must be in byte increments";
				for (r = 0; i > r; r += 2) {
					if (((e = parseInt(t.substr(r, 2), 16)), isNaN(e)))
						throw "String of HEX type contains invalid characters";
					n[r >>> 3] |= e << (24 - (r % 8) * 4);
				}
				return {
					value: n,
					binLen: 4 * i,
				};
			}
			function i(t) {
				var r,
					e,
					n,
					i,
					o,
					a = [],
					s = 0;
				if (-1 === t.search(/^[a-zA-Z0-9=+\/]+$/))
					throw "Invalid character in base-64 string";
				if (
					((o = t.indexOf("=")),
					(t = t.replace(/\=/g, "")),
					-1 !== o && o < t.length)
				)
					throw "Invalid '=' found in base-64 string";
				for (r = 0; r < t.length; r += 4) {
					for (i = t.substr(r, 4), n = 0, e = 0; e < i.length; e += 1)
						n |=
							"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(
								i[e],
							) <<
							(18 - 6 * e);
					for (e = 0; e < i.length - 1; e += 1)
						(a[s >> 2] |= ((n >>> (16 - 8 * e)) & 255) << (24 - (s % 4) * 8)),
							(s += 1);
				}
				return {
					value: a,
					binLen: 8 * s,
				};
			}
			function o(t, r) {
				var e,
					n,
					i = "0123456789abcdef",
					o = "",
					a = 4 * t.length;
				for (e = 0; a > e; e += 1)
					o +=
						i.charAt(((n = t[e >>> 2] >>> (8 * (3 - (e % 4)))) >>> 4) & 15) +
						i.charAt(15 & n);
				return r.outputUpper ? o.toUpperCase() : o;
			}
			function a(t, r) {
				var e,
					n,
					i,
					o = "",
					a = 4 * t.length;
				for (e = 0; a > e; e += 3)
					for (
						i =
							(((t[e >>> 2] >>> (8 * (3 - (e % 4)))) & 255) << 16) |
							(((t[(e + 1) >>> 2] >>> (8 * (3 - ((e + 1) % 4)))) & 255) << 8) |
							((t[(e + 2) >>> 2] >>> (8 * (3 - ((e + 2) % 4)))) & 255),
							n = 0;
						4 > n;
						n += 1
					)
						o +=
							8 * e + 6 * n <= 32 * t.length
								? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
										(i >>> (6 * (3 - n))) & 63,
								  )
								: r.b64Pad;
				return o;
			}
			function s(t) {
				var r = {
					outputUpper: !1,
					b64Pad: "=",
				};
				try {
					t.hasOwnProperty("outputUpper") && (r.outputUpper = t.outputUpper),
						t.hasOwnProperty("b64Pad") && (r.b64Pad = t.b64Pad);
				} catch (e) {}
				if ("boolean" != typeof r.outputUpper)
					throw "Invalid outputUpper formatting option";
				if ("string" != typeof r.b64Pad)
					throw "Invalid b64Pad formatting option";
				return r;
			}
			function h(t, r) {
				return (t << r) | (t >>> (32 - r));
			}
			function u(t, r) {
				return (t >>> r) | (t << (32 - r));
			}
			function l(t, e) {
				var n = new r(t.highOrder, t.lowOrder);
				return 32 >= e
					? new r(
							((n.highOrder >>> e) & 4294967295) |
								((n.lowOrder << (32 - e)) & 4294967295),
							((n.lowOrder >>> e) & 4294967295) |
								((n.highOrder << (32 - e)) & 4294967295),
					  )
					: new r(
							((n.lowOrder >>> (e - 32)) & 4294967295) |
								((n.highOrder << (64 - e)) & 4294967295),
							((n.highOrder >>> (e - 32)) & 4294967295) |
								((n.lowOrder << (64 - e)) & 4294967295),
					  );
			}
			function f(t, r) {
				return t >>> r;
			}
			function c(t, e) {
				return 32 >= e
					? new r(
							t.highOrder >>> e,
							(t.lowOrder >>> e) | ((t.highOrder << (32 - e)) & 4294967295),
					  )
					: new r(0, t.highOrder >>> (e - 32));
			}
			function g(t, r, e) {
				return t ^ r ^ e;
			}
			function p(t, r, e) {
				return (t & r) ^ (~t & e);
			}
			function d(t, e, n) {
				return new r(
					(t.highOrder & e.highOrder) ^ (~t.highOrder & n.highOrder),
					(t.lowOrder & e.lowOrder) ^ (~t.lowOrder & n.lowOrder),
				);
			}
			function m(t, r, e) {
				return (t & r) ^ (t & e) ^ (r & e);
			}
			function w(t, e, n) {
				return new r(
					(t.highOrder & e.highOrder) ^
						(t.highOrder & n.highOrder) ^
						(e.highOrder & n.highOrder),
					(t.lowOrder & e.lowOrder) ^
						(t.lowOrder & n.lowOrder) ^
						(e.lowOrder & n.lowOrder),
				);
			}
			function v(t) {
				return u(t, 2) ^ u(t, 13) ^ u(t, 22);
			}
			function b(t) {
				var e = l(t, 28),
					n = l(t, 34),
					i = l(t, 39);
				return new r(
					e.highOrder ^ n.highOrder ^ i.highOrder,
					e.lowOrder ^ n.lowOrder ^ i.lowOrder,
				);
			}
			function S(t) {
				return u(t, 6) ^ u(t, 11) ^ u(t, 25);
			}
			function y(t) {
				var e = l(t, 14),
					n = l(t, 18),
					i = l(t, 41);
				return new r(
					e.highOrder ^ n.highOrder ^ i.highOrder,
					e.lowOrder ^ n.lowOrder ^ i.lowOrder,
				);
			}
			function A(t) {
				return u(t, 7) ^ u(t, 18) ^ f(t, 3);
			}
			function O(t) {
				var e = l(t, 1),
					n = l(t, 8),
					i = c(t, 7);
				return new r(
					e.highOrder ^ n.highOrder ^ i.highOrder,
					e.lowOrder ^ n.lowOrder ^ i.lowOrder,
				);
			}
			function B(t) {
				return u(t, 17) ^ u(t, 19) ^ f(t, 10);
			}
			function _(t) {
				var e = l(t, 19),
					n = l(t, 61),
					i = c(t, 6);
				return new r(
					e.highOrder ^ n.highOrder ^ i.highOrder,
					e.lowOrder ^ n.lowOrder ^ i.lowOrder,
				);
			}
			function T(t, r) {
				var e = (65535 & t) + (65535 & r);
				return (
					((65535 & ((t >>> 16) + (r >>> 16) + (e >>> 16))) << 16) | (65535 & e)
				);
			}
			function H(t, r, e, n) {
				var i = (65535 & t) + (65535 & r) + (65535 & e) + (65535 & n);
				return (
					((65535 &
						((t >>> 16) + (r >>> 16) + (e >>> 16) + (n >>> 16) + (i >>> 16))) <<
						16) |
					(65535 & i)
				);
			}
			function C(t, r, e, n, i) {
				var o =
					(65535 & t) + (65535 & r) + (65535 & e) + (65535 & n) + (65535 & i);
				return (
					((65535 &
						((t >>> 16) +
							(r >>> 16) +
							(e >>> 16) +
							(n >>> 16) +
							(i >>> 16) +
							(o >>> 16))) <<
						16) |
					(65535 & o)
				);
			}
			function U(t, e) {
				var n, i, o;
				return (
					(o =
						((65535 &
							(i =
								(t.lowOrder >>> 16) +
								(e.lowOrder >>> 16) +
								((n = (65535 & t.lowOrder) + (65535 & e.lowOrder)) >>> 16))) <<
							16) |
						(65535 & n)),
					new r(
						((65535 &
							(i =
								(t.highOrder >>> 16) +
								(e.highOrder >>> 16) +
								((n =
									(65535 & t.highOrder) +
									(65535 & e.highOrder) +
									(i >>> 16)) >>>
									16))) <<
							16) |
							(65535 & n),
						o,
					)
				);
			}
			function I(t, e, n, i) {
				var o, a, s;
				return (
					(s =
						((65535 &
							(a =
								(t.lowOrder >>> 16) +
								(e.lowOrder >>> 16) +
								(n.lowOrder >>> 16) +
								(i.lowOrder >>> 16) +
								((o =
									(65535 & t.lowOrder) +
									(65535 & e.lowOrder) +
									(65535 & n.lowOrder) +
									(65535 & i.lowOrder)) >>>
									16))) <<
							16) |
						(65535 & o)),
					new r(
						((65535 &
							(a =
								(t.highOrder >>> 16) +
								(e.highOrder >>> 16) +
								(n.highOrder >>> 16) +
								(i.highOrder >>> 16) +
								((o =
									(65535 & t.highOrder) +
									(65535 & e.highOrder) +
									(65535 & n.highOrder) +
									(65535 & i.highOrder) +
									(a >>> 16)) >>>
									16))) <<
							16) |
							(65535 & o),
						s,
					)
				);
			}
			function R(t, e, n, i, o) {
				var a, s, h;
				return (
					(h =
						((65535 &
							(s =
								(t.lowOrder >>> 16) +
								(e.lowOrder >>> 16) +
								(n.lowOrder >>> 16) +
								(i.lowOrder >>> 16) +
								(o.lowOrder >>> 16) +
								((a =
									(65535 & t.lowOrder) +
									(65535 & e.lowOrder) +
									(65535 & n.lowOrder) +
									(65535 & i.lowOrder) +
									(65535 & o.lowOrder)) >>>
									16))) <<
							16) |
						(65535 & a)),
					new r(
						((65535 &
							(s =
								(t.highOrder >>> 16) +
								(e.highOrder >>> 16) +
								(n.highOrder >>> 16) +
								(i.highOrder >>> 16) +
								(o.highOrder >>> 16) +
								((a =
									(65535 & t.highOrder) +
									(65535 & e.highOrder) +
									(65535 & n.highOrder) +
									(65535 & i.highOrder) +
									(65535 & o.highOrder) +
									(s >>> 16)) >>>
									16))) <<
							16) |
							(65535 & a),
						h,
					)
				);
			}
			function E(t, r) {
				var e,
					n,
					i,
					o,
					a,
					s,
					u,
					l,
					f,
					c = [],
					d = p,
					w = g,
					v = m,
					b = h,
					S = T,
					y = C,
					A = [1732584193, 4023233417, 2562383102, 271733878, 3285377520],
					O = [
						1518500249, 1518500249, 1518500249, 1518500249, 1518500249,
						1518500249, 1518500249, 1518500249, 1518500249, 1518500249,
						1518500249, 1518500249, 1518500249, 1518500249, 1518500249,
						1518500249, 1518500249, 1518500249, 1518500249, 1518500249,
						1859775393, 1859775393, 1859775393, 1859775393, 1859775393,
						1859775393, 1859775393, 1859775393, 1859775393, 1859775393,
						1859775393, 1859775393, 1859775393, 1859775393, 1859775393,
						1859775393, 1859775393, 1859775393, 1859775393, 1859775393,
						2400959708, 2400959708, 2400959708, 2400959708, 2400959708,
						2400959708, 2400959708, 2400959708, 2400959708, 2400959708,
						2400959708, 2400959708, 2400959708, 2400959708, 2400959708,
						2400959708, 2400959708, 2400959708, 2400959708, 2400959708,
						3395469782, 3395469782, 3395469782, 3395469782, 3395469782,
						3395469782, 3395469782, 3395469782, 3395469782, 3395469782,
						3395469782, 3395469782, 3395469782, 3395469782, 3395469782,
						3395469782, 3395469782, 3395469782, 3395469782, 3395469782,
					];
				for (
					t[r >>> 5] |= 128 << (24 - (r % 32)),
						t[15 + (((r + 65) >>> 9) << 4)] = r,
						f = t.length,
						u = 0;
					f > u;
					u += 16
				) {
					for (
						e = A[0], n = A[1], i = A[2], o = A[3], a = A[4], l = 0;
						80 > l;
						l += 1
					)
						(c[l] =
							16 > l
								? t[l + u]
								: b(c[l - 3] ^ c[l - 8] ^ c[l - 14] ^ c[l - 16], 1)),
							(s = y(
								b(e, 5),
								20 > l
									? d(n, i, o)
									: 40 > l
									? w(n, i, o)
									: 60 > l
									? v(n, i, o)
									: w(n, i, o),
								a,
								O[l],
								c[l],
							)),
							(a = o),
							(o = i),
							(i = b(n, 30)),
							(n = e),
							(e = s);
					(A[0] = S(e, A[0])),
						(A[1] = S(n, A[1])),
						(A[2] = S(i, A[2])),
						(A[3] = S(o, A[3])),
						(A[4] = S(a, A[4]));
				}
				return A;
			}
			function D(t, e, n) {
				var i,
					o,
					a,
					s,
					h,
					u,
					l,
					f,
					c,
					g,
					E,
					D,
					x,
					P,
					N,
					L,
					F,
					k,
					X,
					V,
					W,
					z,
					j,
					q,
					K,
					G,
					Z,
					J,
					Q,
					Y,
					$ = [];
				if (("SHA-224" === n || "SHA-256" === n) && 2 & M)
					(D = 64),
						(x = 15 + (((e + 65) >>> 9) << 4)),
						(L = 16),
						(F = 1),
						(Z = Number),
						(k = T),
						(X = H),
						(V = C),
						(W = A),
						(z = B),
						(j = v),
						(q = S),
						(G = m),
						(K = p),
						(J = [
							1116352408, 1899447441, 3049323471, 3921009573, 961987163,
							1508970993, 2453635748, 2870763221, 3624381080, 310598401,
							607225278, 1426881987, 1925078388, 2162078206, 2614888103,
							3248222580, 3835390401, 4022224774, 264347078, 604807628,
							770255983, 1249150122, 1555081692, 1996064986, 2554220882,
							2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
							113926993, 338241895, 666307205, 773529912, 1294757372,
							1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
							2730485921, 2820302411, 3259730800, 3345764771, 3516065817,
							3600352804, 4094571909, 275423344, 430227734, 506948616,
							659060556, 883997877, 958139571, 1322822218, 1537002063,
							1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
							2428436474, 2756734187, 3204031479, 3329325298,
						]),
						(E =
							"SHA-224" === n
								? [
										3238371032, 914150663, 812702999, 4144912697, 4290775857,
										1750603025, 1694076839, 3204075428,
								  ]
								: [
										1779033703, 3144134277, 1013904242, 2773480762, 1359893119,
										2600822924, 528734635, 1541459225,
								  ]);
				else {
					if (("SHA-384" !== n && "SHA-512" !== n) || !(4 & M))
						throw "Unexpected error in SHA-2 implementation";
					(D = 80),
						(x = 31 + (((e + 128) >>> 10) << 5)),
						(L = 32),
						(F = 2),
						(k = U),
						(X = I),
						(V = R),
						(W = O),
						(z = _),
						(j = b),
						(q = y),
						(G = w),
						(K = d),
						(J = [
							new (Z = r)(1116352408, 3609767458),
							new Z(1899447441, 602891725),
							new Z(3049323471, 3964484399),
							new Z(3921009573, 2173295548),
							new Z(961987163, 4081628472),
							new Z(1508970993, 3053834265),
							new Z(2453635748, 2937671579),
							new Z(2870763221, 3664609560),
							new Z(3624381080, 2734883394),
							new Z(310598401, 1164996542),
							new Z(607225278, 1323610764),
							new Z(1426881987, 3590304994),
							new Z(1925078388, 4068182383),
							new Z(2162078206, 991336113),
							new Z(2614888103, 633803317),
							new Z(3248222580, 3479774868),
							new Z(3835390401, 2666613458),
							new Z(4022224774, 944711139),
							new Z(264347078, 2341262773),
							new Z(604807628, 2007800933),
							new Z(770255983, 1495990901),
							new Z(1249150122, 1856431235),
							new Z(1555081692, 3175218132),
							new Z(1996064986, 2198950837),
							new Z(2554220882, 3999719339),
							new Z(2821834349, 766784016),
							new Z(2952996808, 2566594879),
							new Z(3210313671, 3203337956),
							new Z(3336571891, 1034457026),
							new Z(3584528711, 2466948901),
							new Z(113926993, 3758326383),
							new Z(338241895, 168717936),
							new Z(666307205, 1188179964),
							new Z(773529912, 1546045734),
							new Z(1294757372, 1522805485),
							new Z(1396182291, 2643833823),
							new Z(1695183700, 2343527390),
							new Z(1986661051, 1014477480),
							new Z(2177026350, 1206759142),
							new Z(2456956037, 344077627),
							new Z(2730485921, 1290863460),
							new Z(2820302411, 3158454273),
							new Z(3259730800, 3505952657),
							new Z(3345764771, 106217008),
							new Z(3516065817, 3606008344),
							new Z(3600352804, 1432725776),
							new Z(4094571909, 1467031594),
							new Z(275423344, 851169720),
							new Z(430227734, 3100823752),
							new Z(506948616, 1363258195),
							new Z(659060556, 3750685593),
							new Z(883997877, 3785050280),
							new Z(958139571, 3318307427),
							new Z(1322822218, 3812723403),
							new Z(1537002063, 2003034995),
							new Z(1747873779, 3602036899),
							new Z(1955562222, 1575990012),
							new Z(2024104815, 1125592928),
							new Z(2227730452, 2716904306),
							new Z(2361852424, 442776044),
							new Z(2428436474, 593698344),
							new Z(2756734187, 3733110249),
							new Z(3204031479, 2999351573),
							new Z(3329325298, 3815920427),
							new Z(3391569614, 3928383900),
							new Z(3515267271, 566280711),
							new Z(3940187606, 3454069534),
							new Z(4118630271, 4000239992),
							new Z(116418474, 1914138554),
							new Z(174292421, 2731055270),
							new Z(289380356, 3203993006),
							new Z(460393269, 320620315),
							new Z(685471733, 587496836),
							new Z(852142971, 1086792851),
							new Z(1017036298, 365543100),
							new Z(1126000580, 2618297676),
							new Z(1288033470, 3409855158),
							new Z(1501505948, 4234509866),
							new Z(1607167915, 987167468),
							new Z(1816402316, 1246189591),
						]),
						(E =
							"SHA-384" === n
								? [
										new Z(3418070365, 3238371032),
										new Z(1654270250, 914150663),
										new Z(2438529370, 812702999),
										new Z(355462360, 4144912697),
										new Z(1731405415, 4290775857),
										new Z(41048885895, 1750603025),
										new Z(3675008525, 1694076839),
										new Z(1203062813, 3204075428),
								  ]
								: [
										new Z(1779033703, 4089235720),
										new Z(3144134277, 2227873595),
										new Z(1013904242, 4271175723),
										new Z(2773480762, 1595750129),
										new Z(1359893119, 2917565137),
										new Z(2600822924, 725511199),
										new Z(528734635, 4215389547),
										new Z(1541459225, 327033209),
								  ]);
				}
				for (
					t[e >>> 5] |= 128 << (24 - (e % 32)), t[x] = e, Q = t.length, P = 0;
					Q > P;
					P += L
				) {
					for (
						i = E[0],
							o = E[1],
							a = E[2],
							s = E[3],
							h = E[4],
							u = E[5],
							l = E[6],
							f = E[7],
							N = 0;
						D > N;
						N += 1
					)
						($[N] =
							16 > N
								? new Z(t[N * F + P], t[N * F + P + 1])
								: X(z($[N - 2]), $[N - 7], W($[N - 15]), $[N - 16])),
							(c = V(f, q(h), K(h, u, l), J[N], $[N])),
							(g = k(j(i), G(i, o, a))),
							(f = l),
							(l = u),
							(u = h),
							(h = k(s, c)),
							(s = a),
							(a = o),
							(o = i),
							(i = k(c, g));
					(E[0] = k(i, E[0])),
						(E[1] = k(o, E[1])),
						(E[2] = k(a, E[2])),
						(E[3] = k(s, E[3])),
						(E[4] = k(h, E[4])),
						(E[5] = k(u, E[5])),
						(E[6] = k(l, E[6])),
						(E[7] = k(f, E[7]));
				}
				if ("SHA-224" === n && 2 & M)
					Y = [E[0], E[1], E[2], E[3], E[4], E[5], E[6]];
				else if ("SHA-256" === n && 2 & M) Y = E;
				else if ("SHA-384" === n && 4 & M)
					Y = [
						E[0].highOrder,
						E[0].lowOrder,
						E[1].highOrder,
						E[1].lowOrder,
						E[2].highOrder,
						E[2].lowOrder,
						E[3].highOrder,
						E[3].lowOrder,
						E[4].highOrder,
						E[4].lowOrder,
						E[5].highOrder,
						E[5].lowOrder,
					];
				else {
					if (!("SHA-512" === n && 4 & M))
						throw "Unexpected error in SHA-2 implementation";
					Y = [
						E[0].highOrder,
						E[0].lowOrder,
						E[1].highOrder,
						E[1].lowOrder,
						E[2].highOrder,
						E[2].lowOrder,
						E[3].highOrder,
						E[3].lowOrder,
						E[4].highOrder,
						E[4].lowOrder,
						E[5].highOrder,
						E[5].lowOrder,
						E[6].highOrder,
						E[6].lowOrder,
						E[7].highOrder,
						E[7].lowOrder,
					];
				}
				return Y;
			}
			var M = 7;
			t.jsSHA = function (t, r, h) {
				var u,
					l = null,
					f = null,
					c = null,
					g = null,
					p = null,
					d = 0,
					m = [0],
					w = null;
				if (8 !== (u = void 0 !== h ? h : 8) && 16 !== u)
					throw "charSize must be 8 or 16";
				if ("HEX" === r) {
					if (0 != t.length % 2)
						throw "srcString of HEX type must be in byte increments";
					(w = n(t)), (d = w.binLen), (m = w.value);
				} else if ("ASCII" === r || "TEXT" === r)
					(w = e(t, u)), (d = w.binLen), (m = w.value);
				else {
					if ("B64" !== r) throw "inputFormat must be HEX, TEXT, ASCII, or B64";
					(w = i(t)), (d = w.binLen), (m = w.value);
				}
				(this.getHash = function (t, r, e) {
					var n = null,
						i = m.slice(),
						h = "";
					switch (r) {
						case "HEX":
							n = o;
							break;
						case "B64":
							n = a;
							break;
						default:
							throw "format must be HEX or B64";
					}
					if ("SHA-1" === t && 1 & M)
						null === l && (l = E(i, d)), (h = n(l, s(e)));
					else if ("SHA-224" === t && 2 & M)
						null === f && (f = D(i, d, t)), (h = n(f, s(e)));
					else if ("SHA-256" === t && 2 & M)
						null === c && (c = D(i, d, t)), (h = n(c, s(e)));
					else if ("SHA-384" === t && 4 & M)
						null === g && (g = D(i, d, t)), (h = n(g, s(e)));
					else {
						if (!("SHA-512" === t && 4 & M))
							throw "Chosen SHA variant is not supported";
						null === p && (p = D(i, d, t)), (h = n(p, s(e)));
					}
					return h;
				}),
					(this.getHMAC = function (t, r, h, l, f) {
						var c,
							g,
							p,
							w,
							v,
							b,
							S,
							y,
							A,
							O = [],
							B = [],
							_ = null;
						switch (l) {
							case "HEX":
								c = o;
								break;
							case "B64":
								c = a;
								break;
							default:
								throw "outputFormat must be HEX or B64";
						}
						if ("SHA-1" === h && 1 & M) (p = 64), (A = 160);
						else if ("SHA-224" === h && 2 & M) (p = 64), (A = 224);
						else if ("SHA-256" === h && 2 & M) (p = 64), (A = 256);
						else if ("SHA-384" === h && 4 & M) (p = 128), (A = 384);
						else {
							if (!("SHA-512" === h && 4 & M))
								throw "Chosen SHA variant is not supported";
							(p = 128), (A = 512);
						}
						if ("HEX" === r) (y = (_ = n(t)).binLen), (g = _.value);
						else if ("ASCII" === r || "TEXT" === r)
							(y = (_ = e(t, u)).binLen), (g = _.value);
						else {
							if ("B64" !== r)
								throw "inputFormat must be HEX, TEXT, ASCII, or B64";
							(y = (_ = i(t)).binLen), (g = _.value);
						}
						if (((w = 8 * p), (S = p / 4 - 1), y / 8 > p)) {
							if ("SHA-1" === h && 1 & M) g = E(g, y);
							else {
								if (!(6 & M)) throw "Unexpected error in HMAC implementation";
								g = D(g, y, h);
							}
							g[S] &= 4294967040;
						} else p > y / 8 && (g[S] &= 4294967040);
						for (v = 0; S >= v; v += 1)
							(O[v] = 909522486 ^ g[v]), (B[v] = 1549556828 ^ g[v]);
						if ("SHA-1" === h && 1 & M)
							b = E(B.concat(E(O.concat(m), w + d)), w + A);
						else {
							if (!(6 & M)) throw "Unexpected error in HMAC implementation";
							b = D(B.concat(D(O.concat(m), w + d, h)), w + A, h);
						}
						return c(b, s(f));
					});
			};
		})),
		(Base64 = {}),
		(Base64.byteToCharMap_ = null),
		(Base64.charToByteMap_ = null),
		(Base64.byteToCharMapWebSafe_ = null),
		(Base64.charToByteMapWebSafe_ = null),
		(Base64.ENCODED_VALS_BASE =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
		(Base64.ENCODED_VALS = Base64.ENCODED_VALS_BASE + "+/="),
		(Base64.ENCODED_VALS_WEBSAFE = Base64.ENCODED_VALS_BASE + "-_."),
		(Base64.encodeByteArray = function (t, r) {
			Base64.init_();
			for (
				var e = r ? Base64.byteToCharMapWebSafe_ : Base64.byteToCharMap_,
					n = [],
					i = 0;
				i < t.length;
				i += 3
			) {
				var o = t[i],
					a = i + 1 < t.length,
					s = a ? t[i + 1] : 0,
					h = i + 2 < t.length,
					u = h ? t[i + 2] : 0,
					l = ((15 & s) << 2) | (u >> 6),
					f = 63 & u;
				h || ((f = 64), a || (l = 64)),
					n.push(e[o >> 2], e[((3 & o) << 4) | (s >> 4)], e[l], e[f]);
			}
			return n.join("");
		}),
		(Base64.init_ = function () {
			if (!Base64.byteToCharMap_) {
				(Base64.byteToCharMap_ = {}),
					(Base64.charToByteMap_ = {}),
					(Base64.byteToCharMapWebSafe_ = {}),
					(Base64.charToByteMapWebSafe_ = {});
				for (var t = 0; t < Base64.ENCODED_VALS.length; t++)
					(Base64.byteToCharMap_[t] = Base64.ENCODED_VALS.charAt(t)),
						(Base64.charToByteMap_[Base64.byteToCharMap_[t]] = t),
						(Base64.byteToCharMapWebSafe_[t] =
							Base64.ENCODED_VALS_WEBSAFE.charAt(t)),
						(Base64.charToByteMapWebSafe_[Base64.byteToCharMapWebSafe_[t]] = t);
			}
		});
	function encryptPassword(t, r, e, n) {
		return ame2eea.encryptPinForAM(t, r, e, n, "SHA-1");
	}

	exports.ame2eeTools = ame2eea;
})(ame2eeF);

export default ame2eeF.ame2eeTools;
