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

var SecureChannelSAM = Class.create({
	/** @lends SecureChannelSAM */
	
	/**
	 *  @class Hardware-assisted implementation of a Secure Channel
	 *  @param {PlugupSAM} sam Plug-up v2 SAM object
	 *  @param {Number} samKeysetVersion Plug-up v2 SAM Context Keyset version to use for this session
	 *  @param {Number} samKeysetId Plug-up v2 SAM Context Keyset id to use for this session
	 *  @param {Number} flags Plug-up v2 specific flags options to use for this session
	 *  @param {ByteString} [fixedRandom] optional fixed random to use
	 *  @constructs
	 */		
	initialize:function(sam, samKeysetVersion, samKeysetId, flags, fixedRandom) {
		this.sessions = {};
		this.sam = sam;
		this.samKeysetVersion = samKeysetVersion;
		this.samKeysetId = samKeysetId;
		this.flags = flags;
		this.fixedRandom = fixedRandom;
	},
	
	computeCMAC: function(session, data) {
		var work;
		// Modify the APDU if needed
		if ((session['scpOptions'] & SecureChannelSAM.GP_OPTION_CMAC_ON_UNMODIFIED_APDU) == 0) {
			work = Convert.toHexByte((data.byteAt(0) & 0xFC) | 0x04);
			work += data.bytes(1, 3).toStringIE(HEX);
			work += Convert.toHexByte(data.byteAt(4) + 8);
			if (data.length > 5) {
				work += data.bytes(5).toStringIE(HEX);
			}
			work = new ByteString(work, HEX);
		}
		else {
			 work = new ByteString(data.toStringIE(HEX), HEX);
		}		
		// Compute the retail mac, salting the mac if necessary
		// Salt the mac if necessary
		if (((session['scpOptions'] & SecureChannelSAM.GP_OPTION_ICV_ENCRYPTED) != 0) && (!session['firstApdu'])) {
			var result = this.sam.signCmacUpdate(this.samKeysetVersion, this.samKeysetId, undefined, session['cmacKey'], session['cmac']);
			session['cmac'] = this.sam.signCmacFinal(this.samKeysetVersion, this.samKeysetId, result['iv'], result['signatureContext'], session['cmacKey'], work);
		}		
		else {
			if (session['firstApdu']) {
				session['firstApdu'] = false;
			}
			session['cmac'] = this.sam.signCmac(this.samKeysetVersion, this.samKeysetId, session['cmac'], session['cmacKey'], work);
		}
		return session['cmac'];
	},
	
	generateRandomHexString: function(size) {
		var digits = '0123456789abcdef';
		var result = "";
		for (var i=0; i<2 * size; i++) {
			result += digits.charAt(Math.floor(Math.random() * 16));
		}
		return result;
	},

	setDiversifier1 : function(diversifier1, passToTarget) {
		if (typeof diversifier1 != "undefined") {
			if (!(diversifier1 instanceof ByteString)) {
				throw "Invalid diversifier";
			}
			if (!(diversifier1.length == 0x10)) {
				throw "Invalid diversifier length";
			}
		}
		this.diversifier1 = diversifier1;
		if (passToTarget) {
			this.salt = diversifier1;
		}
	},

	setDiversifier2 : function(diversifier2, passToTarget) {
		if (typeof diversifier2 != "undefined") {
			if (!(diversifier2 instanceof ByteString)) {
				throw "Invalid diversifier";
			}
			if (!(diversifier2.length == 0x10)) {
				throw "Invalid diversifier length";
			}
		}
		this.diversifier2 = diversifier2;
		if (passToTarget) {
			this.salt = diversifier2;
		}
	},                
		
	openSession: function(scpOptions, scpSecurityLevel, keyVersion) {
		// Create the dummy session object and return the INITIALIZE UPDATE APDU
		var session = {};
		session['scpOptions'] = scpOptions;
		session['scpSecurityLevel'] = scpSecurityLevel;
		session['keyVersion'] = keyVersion;
		var apdu = "D050" + Convert.toHexDigit(keyVersion); 
		if (typeof this.salt == "undefined") {
			apdu += "0008";
		}
		else {
			apdu += "1018";
		}
		var hostChallenge = "";
		if (typeof this.fixedRandom == "undefined") {
			hostChallenge = this.generateRandomHexString(8);
		}
		else {
			hostChallenge = this.fixedRandom;
		}
		apdu += hostChallenge;
		if (typeof this.salt != "undefined") {
			apdu += this.salt.toString(HEX);
		}
		session['hostChallenge'] = hostChallenge;
		this.sessions[hostChallenge] = session;
		var result = {};
		result['sessionID'] = hostChallenge;
		result['data'] = new ByteString(apdu, HEX);
		return result;
	},
		
	
	getExternalAuthenticateAPDU: function(sessionUUID, keyIds, initializeUpdateResponse, diversificationAlgorithm) {
		var session = this.sessions[sessionUUID];
		if (typeof session == "undefined") {
			throw "Invalid session (external authenticate)";
		}
		// Diversify the keys
		var sequenceCounter = initializeUpdateResponse.bytes(12, 2);		
		var result = this.sam.diversifyGP(this.samKeysetVersion, this.samKeysetId, keyIds, this.flags, sequenceCounter, this.diversifier1, this.diversifier2); 
		session['cencKey'] = result['cenc'];
		session['cmacKey'] = result['cmac'];
		if (typeof result['dek'] != 'undefined') {
			session['dekKey'] = result['dek'];
		}
		if (typeof result['rmac'] != 'undefined') {
			session['rmacKey'] = result['rmac'];
		}
		if (typeof result['renc'] != 'undefined') {
			session['rencKey'] = result['renc'];
		}
		session['cmac'] = new ByteString("0000000000000000", HEX);		
		session['firstApdu'] = true;

		// Check the card cryptogram
		var work = session['hostChallenge'] + initializeUpdateResponse.bytes(12, 8).toStringIE(HEX);
		var cardCryptogram = this.sam.signEnc(this.samKeysetVersion, this.samKeysetId, session['cencKey'], new ByteString(work, HEX));
		if (!cardCryptogram.equals(initializeUpdateResponse.bytes(20, 8))) {
			throw "Invalid card cryptogram";
		}
		// Compute the host cryptogram
		work = initializeUpdateResponse.bytes(12, 8).toStringIE(HEX) + session['hostChallenge'];
		var hostCryptogram = this.sam.signEnc(this.samKeysetVersion, this.samKeysetId, session['cencKey'], new ByteString(work, HEX));
		var externalAuthenticate = "D082" + Convert.toHexDigit(session['scpSecurityLevel']) + "0008";
		externalAuthenticate = new ByteString(externalAuthenticate, HEX).concat(hostCryptogram);
		var cmac = this.computeCMAC(session, externalAuthenticate);
		session['rmac'] = cmac;
		externalAuthenticate = externalAuthenticate.concat(cmac);		
		// Flag the secure messaging
		work = Convert.toHexByte(externalAuthenticate.byteAt(0) | 0x04);
		work += externalAuthenticate.bytes(1, 3).toStringIE(HEX);
		work += Convert.toHexByte(externalAuthenticate.byteAt(4) + 8);
		work += externalAuthenticate.bytes(5).toStringIE(HEX);
		return new ByteString(work, HEX);		
	},
	
	processSensitiveData: function(session, data, sensitiveData, encrypt) {
		var processSensitiveDataBlock = function(original, sensitiveData) {
			var offset = sensitiveData['offset'];
			var length = sensitiveData['length'];
			if (encrypt) {
				offset += 5;
			}
			if ((typeof offset == "undefined") || (typeof length == "undefined")) {
				throw "Invalid sensitive data";
			}
			if (!encrypt) {
				throw "Decryption of sensitive data is unsupported";
			}					
			var target = original.bytes(0, offset);
			var part = original.bytes(offset, length);
			target = target.concat(this.sam.cipherDek(this.samKeysetVersion, this.samKeysetId, session['dekKey'], part));
			target = target.concat(original.bytes(offset + length));
			return target;
		}
		if (typeof sensitiveData != "undefined") {
			if (sensitiveData instanceof Array) { 
				for (var i=0; i<sensitiveData.length; i++) {
					data = processSensitiveDataBlock(data, sensitiveData[i]);
				}
			}
			else {
				data = processSensitiveDataBlock(data, sensitiveData);
			}
		}
		return data;
	},	
		
	wrapAPDU: function(sessionUUID, apdu, sensitiveData) {
		var session = this.sessions[sessionUUID];
		var cmac;
		var target;
		if (typeof session == "undefined") {
			throw "Invalid session (wrap)";
		}
		apdu = this.processSensitiveData(session, apdu, sensitiveData, 1);
		var resultLength = apdu.length;
		target = new ByteString(apdu.toStringIE(HEX), HEX);		
		if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_RMAC) != 0) {
			work = new ByteString(Convert.toHexByte(apdu.byteAt(0) & 0xFC), HEX).concat(apdu.bytes(1));
			var result = this.sam.signRmacCommand(this.samKeysetVersion, this.samKeysetId, session['rmac'], session['rmacKey'], work);
			session['samContext'] = result;
      	}      
		if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_CDECRYPTION) != 0) {
			var cipherDataBlock = this.sam.cipherEnc(this.samKeysetVersion, this.samKeysetId, session['cencKey'], (apdu.length > 5 ? apdu.bytes(5) : new ByteString("", HEX)));
			target = target.bytes(0, 4).toStringIE(HEX) + Convert.toHexByte(cipherDataBlock.length) + cipherDataBlock.toStringIE(HEX);
			target = new ByteString(target, HEX);
		}
		if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_CMAC) != 0) {
			cmac = this.computeCMAC(session, apdu);
			var macTarget = target.bytes(0, 4).toStringIE(HEX) + Convert.toHexByte(target.byteAt(4) + 8);
			if (target.length > 5) {
				macTarget += target.bytes(5).toStringIE(HEX); 
			}
			macTarget += cmac.toStringIE(HEX);
			target = new ByteString(macTarget, HEX);
		}
		if (session['scpSecurityLevel'] != 0) {
			target = Convert.toHexByte(target.byteAt(0) | 4) + target.bytes(1).toStringIE(HEX);
			target = new ByteString(target, HEX);
		}
		return target;	 	
	},
	
	unwrapAPDU: function(sessionUUID, apdu, sensitiveData) {
		var session = this.sessions[sessionUUID];
		if (typeof session == "undefined") {
			throw "Invalid session (unwrap)";
		}
		var sw = apdu.bytes(apdu.length - 2, 2);		
		if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_RENC) != 0) {
	      var enc_data_len = apdu.length - 2; // not sw
    	  var rmac;
      	  if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_RMAC) != 0) {
        	enc_data_len -= 8;
        	rmac = apdu.bytes(apdu.length - 10, 8);
      	  }
      	  if (enc_data_len > 0) {
      
        	// decipher the rdata
        	if ((enc_data_len % 8) != 0) {
          	  throw "Not a valid encrypted data length";
        	}
    		var decipheredData = this.sam.decipherRenc(this.samKeysetVersion, this.samKeysetId, session['rencKey'], apdu.bytes(0, enc_data_len));      
	        // unciphered apdu for rmac checking
    	    if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_RMAC) != 0) {
        	  apdu = decipheredData.concat(rmac).concat(sw);
        	}
        	else {
          		apdu = decipheredData.concat(sw);
        	}

      	  }
      	} 
    	if ((session['scpSecurityLevel'] & SecureChannelSAM.SCP_SECURITY_LEVEL_RMAC) != 0) {
      		if (apdu.length < 10) {
        		throw "Missing RMAC";
      		}
      		var rdata = apdu.bytes(0, apdu.length - 10);
      		var work = Convert.toHexByte(apdu.length - 10);
      		work += rdata.toStringIE(HEX);
      		work += sw.toStringIE(HEX);
	        var work = new ByteString(work, HEX);
			work = this.sam.signRmacResponse(this.samKeysetVersion, this.samKeysetId, session['samContext']['iv'], session['samContext']['signatureContext'], session['rmacKey'], work);	        
	        if (!(work.equals(apdu.bytes(apdu.length - 10, 8)))) {
      		  throw "Invalid RMAC";
      		}
      		session['rmac'] = work;
      		apdu = rdata.concat(sw);
    	}	    	
    	// Discard SW
    	apdu = apdu.bytes(0, apdu.length - 2);
    	// process DEK if needed
		return this.processSensitiveData(session, apdu, sensitiveData, 0);
	},
	
    getPutKeyAPDU: function(sessionUUID, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, unwrapped) {
    	return this._getPutKeyAPDU(sessionUUID, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, false, unwrapped);
    },

    getPutKeyXORAPDU: function(sessionUUID, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, unwrapped) {
    	return this._getPutKeyAPDU(sessionUUID, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, true, unwrapped);
    },

	
	_getPutKeyAPDU: function(sessionUUID, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, xorMode, unwrapped) {
		var session = this.sessions[sessionUUID];
		if (typeof session == "undefined") {
			throw "Invalid session (put key)";
		}
		if (typeof originalKeyVersion != "number") {
			throw "Invalid original key version";
		}
		if (typeof newKeyVersion != "number") {
			throw "Invalid new key version";
		}
		if (typeof keyUsage == "undefined") {
			throw "Invalid key usage";
		}
		if (typeof keyAccess == "undefined") {
			keyAccess = new ByteString("0000", HEX);
		}
		if (!(keyAccess instanceof ByteString)) {
			throw "Invalid key access";
		}
		if (typeof keyDiversifier != "undefined") {
			if (!(keyDiversifier instanceof ByteString) || keyDiversifier.length != 10) {
				throw "Invalid key diversifier";
			}
		}
		var samResult = this.sam.preparePutKey(this.samKeysetVersion, this.samKeysetId, keyIds, session['dekKey'], diversifier1, diversifier2);
		var encryptedKeys = [];
		var kcv = [];		
		for (var i=0; i<3; i++) {
			encryptedKeys.push(samResult[i]['encryptedKey']);
			kcv.push(samResult[i]['kcv']);
		}
		var content = Convert.toHexByte(newKeyVersion);
		for (var i=0; i<3; i++) {
			content += "FF8010" + encryptedKeys[i].toString(HEX) + "03" + kcv[i].toString(HEX);
			content += "01" + Convert.toHexByte(keyUsage) + "02" + keyAccess.toString(HEX);
		}
		if (typeof keyDiversifier != "undefined") {
			content += keyDiversifier.toString(HEX);
		}
		else {
			content += "00000000000000000000";
		}
		var result = "80D8" + Convert.toHexByte(originalKeyVersion) + (!xorMode ? "81" : "82") + Convert.toHexByte(content.length / 2) + content;
		if (unwrapped) {
			return new ByteString(result, HEX);
		}
		return this.wrapAPDU(sessionUUID, new ByteString(result, HEX));				
	},		
	
	closeSession: function(sessionUUID) {
		var session = this.sessions[sessionUUID];
		if (typeof session == "undefined") {
			throw "Invalid session (close)";
		}
		delete this.sessions[sessionUUID];
	}
	
});

SecureChannelSAM.SCP_SECURITY_LEVEL_CMAC = 1;
SecureChannelSAM.SCP_SECURITY_LEVEL_CDECRYPTION = 2;
SecureChannelSAM.SCP_SECURITY_LEVEL_RMAC = 16;
SecureChannelSAM.SCP_SECURITY_LEVEL_RENC = 32;

SecureChannelSAM.GP_OPTION_CMAC_ON_UNMODIFIED_APDU = 2;
SecureChannelSAM.GP_OPTION_ICV_INIT_AID = 8;
SecureChannelSAM.GP_OPTION_ICV_ENCRYPTED = 16;
SecureChannelSAM.GP_OPTION_USE_RMAC = 32;
