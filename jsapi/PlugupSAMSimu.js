/******************************************************************************
 file           : $Id$
 project        : Plug-up v2 API
 author         : $Author$
 ------------------------------------------------------------------------------
 changed on     : $Revision$
 ------------------------------------------------------------------------------
 description    : HID API web bridge
 ------------------------------------------------------------------------------
 Copyright (c) 2012 Ubinity SAS. All rights reserved.
 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 ******************************************************************************/

var PlugupSAMSimu = Class.extend(PlugupSAM, {
	/**@lends PlugupSAMSimu.prototype */
	
	initialize : function() {
		this.keysets = {};
	},
	
	addKeyset : function(keysetId, keyset) {
		if (keyset instanceof ByteString) {
			this.keysets[keysetId] = [ keyset, keyset, keyset];
		}
		else 
		if (keyset instanceof Array) {
			if (keyset.length != 3) {
				throw "Invalid keyset value";
			}
			this.keysets[keysetId] = keyset;
		}
		else {
			throw "Invalid keyset";
		}
	},
	
	_convertKeysetId : function(keysetId) {
		if (typeof keysetId == "number") {
			if (typeof this.keysets[keysetId] == "undefined") {
				throw "Keyset " + keysetId + " is not mapped";
			}
			return this.keysets[keysetId];
		}
		else
		if (keysetId instanceof ByteString) {
			if (keysetId.length == 1) {
				if (typeof this.keysets[keysetId.byteAt(0)] == "undefined") {
					throw "Keyset " + keysetId.byteAt(0) + " is not mapped";
				}
				return this.keysets[keysetId.byteAt(0)];				
			}
			return [keysetId, keysetId, keysetId];
		}
		else
		if (keysetId instanceof Array) {
			return keysetId;
		}
		else {
			throw "Invalid keyset id";
		}
	},	

	diversifyGP : function(samKeysetVersion, samKeysetId, GPKeysetId, flags, sequenceCounter, diversifier1, diversifier2) {
		var keyset = this._convertKeysetId(GPKeysetId);
		if (typeof keyset == "undefined") {
			throw "Unknown keyset";
		}
		var encKey = keyset[0];
		var macKey = keyset[1];
		var dekKey = keyset[2];
		if (typeof diversifier1 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		if (typeof diversifier2 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		var deriveKeySCP02 = function(constant, key) {
			var work = "01" + Convert.toHexByte(constant) + sequenceCounter.toString(HEX);
			work += "000000000000000000000000";
			var des = new DES(key);
			return des.process(new ByteString(work, HEX), DES.ENCRYPT, DES.MODE_CBC);         
		}		
		var result = {};
		result['cenc'] = deriveKeySCP02(0x82, encKey);
		result['cmac'] = deriveKeySCP02(0x01, macKey);
		result['dek'] = deriveKeySCP02(0x81, dekKey);
		result['rmac'] = deriveKeySCP02(0x02, macKey);
		result['renc'] = deriveKeySCP02(0x83, encKey);
		return result;
	},

	deriveCleartext : function(targetKeysetId, diversifier1, diversifier2) {
		var keyset = this._convertKeysetId(GPKeysetId);
		if (typeof keyset == "undefined") {
			throw "Unknown keyset";
		}
		var encKey = keyset[0];
		var macKey = keyset[1];
		var dekKey = keyset[2];
		if (typeof diversifier1 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		if (typeof diversifier2 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		return [encKey, macKey, dekKey];
	},

	preparePutKey : function(samKeysetVersion, samKeysetId, targetKeysetId, sessionKey, diversifier1, diversifier2) {
		var keyset = this._convertKeysetId(targetKeysetId);
		if (typeof keyset == "undefined") {
			throw "Unknown keyset";
		}
		var encKey = keyset[0];
		var macKey = keyset[1];
		var dekKey = keyset[2];
		if (typeof diversifier1 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier1, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		if (typeof diversifier2 != "undefined") {
			var des = new DES(encKey);
			encKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(macKey);
			macKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);
			des = new DES(dekKey);
			dekKey = des.process(new ByteString(diversifier2, HEX), DES.ENCRYPT, DES.MODE_CBC);			
		}
		var computeKCV = function(data) {
			if ((!(data instanceof ByteString)) || (data.length != 16)) {
				throw "Invalid data";
			}
			var des = new DES(data);
			var kcvBlock = new ByteString("0000000000000000", HEX);
			var result = des.process(kcvBlock, DES.ENCRYPT, DES.MODE_ECB);
			return result.bytes(0, 3);
		}
		var result = [];
		var dekEncrypt = new DES(sessionKey);
		var work = [encKey, macKey, dekKey];
		for (var i=0; i<3; i++) {
			var keyMaterial = {};
			keyMaterial['encryptedKey'] = dekEncrypt.process(work[i], DES.ENCRYPT, DES.MODE_ECB);
			keyMaterial['kcv'] = computeKCV(work[i]);
			result.push(keyMaterial);
		}
		return result;
	},

	signEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._cipherEnc(sessionKey, content).bytes(16, 8);
	},

	signCmacUpdate : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
		this.pendingCmac = content;
		var result = {};
		result['iv'] = (typeof iv == "undefined" ? new ByteString("0000000000000000", HEX) : iv);
		result['signatureContext'] = new ByteString("", HEX);
		return result;
	},

	signCmacFinal : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
		var data;
		if (typeof this.pendingCmac != undefined) {
			data = this.pendingCmac.concat(content);
			this.pendingCmac = undefined;
		}
		else {
			data = content;
		}
		return this.signCmac(samKeysetVersion, samKeysetId, iv, sessionKey, data);
	},

    signCmac : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
    	return this._signRetail(iv, sessionKey, content);
    },
    
    _signRetail : function(iv, sessionKey, content) {
    	var work = new ByteString(content.toStringIE(HEX), HEX);
		// Compute the padding
		var padString = new ByteString("8000000000000000", HEX);
		var padLength = 8 - (work.length % 8);
		work = work.concat(padString.bytes(0, padLength));
		// Compute the retail mac
		var macKey1 = sessionKey.bytes(0, 8);
		var macKey2 = sessionKey.bytes(8);
		var des1 = new DES(macKey1);
		work = des1.process(work, DES.ENCRYPT, DES.MODE_CBC, iv);
		work = new DES(macKey2).process(work.bytes(work.length - 8), DES.DECRYPT, DES.MODE_ECB);
		work = des1.process(work, DES.ENCRYPT, DES.MODE_ECB);
		return work;    	
    },

    signRmacCommand : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
    	this.pendingRmac = content;
		var result = {};
		result['iv'] = (typeof iv == "undefined" ? new ByteString("0000000000000000", HEX) : iv);
		result['signatureContext'] = new ByteString("", HEX);
		return result;
    },

	signRmacResponse : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
		var data;
		if (typeof this.pendingRmac != undefined) {
			data = this.pendingRmac.concat(content);
			this.pendingRmac = undefined;
		}
		else {
			data = content;
		}
		return this._signRetail(iv, sessionKey, data);		
	},

	cipherEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._cipherEnc(sessionKey, content);
	},
	
	_cipherEnc : function(sessionKey, content) {
    	var work = new ByteString(content.toStringIE(HEX), HEX);
		// Compute the padding
		var padString = new ByteString("8000000000000000", HEX);
		var padLength = 8 - (work.length % 8);
		work = work.concat(padString.bytes(0, padLength));
		var des = new DES(sessionKey);
		return des.process(work, DES.ENCRYPT, DES.MODE_CBC);
	},

	cipherDek : function(samKeysetVersion, samKeysetId, sessionKey, content) {		
		var des = new DES(sessionKey);
		return des.process(content, DES.ENCRYPT, DES.MODE_ECB);
	},

	decipherRenc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		var des = new DES(sessionKey);
		var work = des.process(content, DES.DECRYPT, DES.MODE_CBC);
		var idx_80 = work.length - 1;
		while((work.byteAt(idx_80) != 0x80) && (idx_80 >= 0)) {
			idx_80--;
		}
		if (idx_80 < 0) {
			throw "Invalid padding";
		}
		return work.bytes(0, idx_80);
	}, 

});
