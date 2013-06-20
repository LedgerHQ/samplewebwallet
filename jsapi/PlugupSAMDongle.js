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

var PlugupSAMDongle = Class.extend(PlugupSAM, {
	/**@lends PlugupSAMDongle.prototype */
	
	/**
	 * @class Communication with Plugup SAM application over a {@link Card} - administrative commands
	 * @param {Object} @Card implementing the Plugup SAM application
	 * @constructs
	 */
	initialize : function(card) {
		if (!(card instanceof Card)) {
			throw "Invalid card";
		}
		this.card = card;
	},
	
	_convertKeysetId : function(keysetId) {
		if (typeof keysetId == "number") {
			return keysetId;
		}
		else
		if (keysetId instanceof ByteString) {
			if (keysetId.length != 1) {
				throw "Invalid keyset id. ByteString must reference the id on 1 byte";
			}
			return keysetId.byteAt(0);
		}
		else {
			throw "Invalid keyset id";
		}
	},

	diversifyGP : function(samKeysetVersion, samKeysetId, GPKeysetId, flags, sequenceCounter, diversifier1, diversifier2) {
		GPKeysetId = this._convertKeysetId(GPKeysetId);
		if (typeof flags == 'undefind') {
			flags = 0;
		}
		if ((typeof diversifier1 != 'undefined') && (typeof diversifier2 == 'undefined')) {
			if (!(diversifier1 instanceof ByteString)) {
				throw "Invalid diversifier1";
			}
			if (diversifier1.length != 16) {
				throw "Invalid diversifier1 length";
			}
			flags |= 0x01;
		}
        if (typeof diversifier2 != 'undefined') {
			if (typeof diversifier1 == 'undefined') {
				throw "Diversifier1 must be present if diversifier2 is defined";
			}
			if (!(diversifier2 instanceof ByteString)) {
				throw "Invalid diversifier2";
			}
			if (diversifier2.length != 16) {
				throw "Invalid diversifier2 length";
			}
			flags |= 0x02;
		}
		if (typeof sequenceCounter == 'number') {
			sequenceCounter = new ByteString(Convert.toHexShort(sequenceCounter), HEX);
		}
		else
		if (!(sequenceCounter instanceof ByteString)) {
			throw "Invalid sequence counter";
		}
		var data = Convert.toHexByte(samKeysetVersion) + Convert.toHexByte(samKeysetId);
		data += Convert.toHexByte(GPKeysetId);
		data += Convert.toHexByte(flags);
		data += sequenceCounter.toString(HEX);	
		if (typeof diversifier1 != 'undefined') {
			data += diversifier1.toString(HEX);
		}
		if (typeof diversifier2 != 'undefined') {
			data += diversifier2.toString(HEX);
		}
		var response = this.card.sendApdu(0xD0, 0x70, 0x00, 0x10, new ByteString(data, HEX), [0x9000]);
		var result = {};
		var offset = 0;
		result['cenc'] = response.bytes(offset, 24);
		offset += 24;
		result['cmac'] = response.bytes(offset, 24);
		offset += 24;
		if ((flags & PlugupSAM.OPTION_GENERATE_DEK) != 0) {
			result['dek'] = response.bytes(offset, 24);
			offset += 24;
		}
		if ((flags & PlugupSAM.OPTION_GENERATE_RMAC) != 0) {
			result['rmac'] = response.bytes(offset, 24);
			offset += 24;
		}	
		if ((flags & PlugupSAM.OPTION_GENERATE_RENC) != 0) {
			result['renc'] = response.bytes(offset, 24);
			offset += 24;
		}
		return result;
	},

	deriveCleartext : function(targetKeysetId, diversifier1, diversifier2) {		
		var flags = 0;
		targetKeysetId = this._convertKeysetId(targetKeysetId);
        if ((typeof diversifier1 != 'undefined') && (typeof diversifier2 == 'undefined')) {
        		if (!(diversifier1 instanceof ByteString)) {
        				throw "Invalid diversifier1";
        		}
        		if (diversifier1.length != 16) {
        				throw "Invalid diversifier1 length";
        		}
        		flags |= 0x01;
        }
        if (typeof diversifier2 != 'undefined') {
        		if (typeof diversifier1 == 'undefined') {
        			throw "Diversifier1 must be present if diversifier2 is defined";
        		}
        		if (!(diversifier2 instanceof ByteString)) {
        			throw "Invalid diversifier2";
        		}
        		if (diversifier2.length != 16) {
        			throw "Invalid diversifier2 length";
        		}
        		flags |= 0x02;
        }
		var data = "0000";
		data += Convert.toHexByte(targetKeysetId);
		data += Convert.toHexByte(flags);
		if (typeof diversifier1 != 'undefined') {
			data += diversifier1.toString(HEX);
		}
		if (typeof diversifier2 != 'undefined') {
			data += diversifier2.toString(HEX);
		}
		var response = this.card.sendApdu(0xD0, 0x70, 0x00, 0x30, new ByteString(data, HEX), [0x9000]);
		var result = [];
		var offset = 0;
		for (var i=0; i<3; i++) {
			var key = response.bytes(offset, 16);
			result.push(key);
			offset += 16;
		}
		return result;
	},

	preparePutKey : function(samKeysetVersion, samKeysetId, targetKeysetId, sessionKey, diversifier1, diversifier2) {
		var flags = 0;
		targetKeysetId = this._convertKeysetId(targetKeysetId);
		if (!(sessionKey instanceof ByteString)) {
			throw "Invalid session key for PUT KEY";
		}		
		if ((typeof diversifier1 != 'undefined') && (typeof diversifier2 == 'undefined')) {
			if (!(diversifier1 instanceof ByteString)) {
				throw "Invalid diversifier1";
			}
			if (diversifier1.length != 16) {
				throw "Invalid diversifier1 length";
			}
			flags |= 0x01;
		}
        if (typeof diversifier2 != 'undefined') {
			if (typeof diversifier1 == 'undefined') {
				throw "Diversifier1 must be present if diversifier2 is defined";
			}
			if (!(diversifier2 instanceof ByteString)) {
				throw "Invalid diversifier2";
			}
			if (diversifier2.length != 16) {
				throw "Invalid diversifier2 length";
			}
			flags |= 0x02;
        }
		var data = Convert.toHexByte(samKeysetVersion) + Convert.toHexByte(samKeysetId);
		data += Convert.toHexByte(targetKeysetId);
		data += Convert.toHexByte(flags);
		data += sessionKey.toString(HEX);
		if (typeof diversifier1 != 'undefined') {
			data += diversifier1.toString(HEX);
		}
		if (typeof diversifier2 != 'undefined') {
			data += diversifier2.toString(HEX);
		}
		var response = this.card.sendApdu(0xD0, 0x70, 0x00, 0x20, new ByteString(data, HEX), [0x9000]);
		var result = [];
		var offset = 0;
		for (var i=0; i<3; i++) {
			var keyResult = {};
			keyResult['encryptedKey'] = response.bytes(offset, 16);
			keyResult['kcv'] = response.bytes(offset + 16, 3);
			result.push(keyResult);
			offset += 19;
		}
		return result;
	},

	signEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._signBlocks(samKeysetVersion, samKeysetId, 0x10, true, undefined, undefined, sessionKey, content);
	},

	signCmacUpdate : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
        return this._signBlocks(samKeysetVersion, samKeysetId, 0x20, false, iv, undefined, sessionKey, content);
	},

	signCmacFinal : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
        return this._signBlocks(samKeysetVersion, samKeysetId, 0x20, true, iv, signatureContext, sessionKey, content);
	},

    signCmac : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
        return this._signBlocks(samKeysetVersion, samKeysetId, 0x20, true, iv, undefined, sessionKey, content);
    },

    signRmacCommand : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
        return this._signBlocks(samKeysetVersion, samKeysetId, 0x30, false, iv, undefined, sessionKey, content);
    },

	signRmacResponse : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
		return this._signBlocks(samKeysetVersion, samKeysetId, 0x30, true, iv, signatureContext, sessionKey, content);
	},

	_signBlocks : function(samKeysetVersion, samKeysetId, type, toLast, iv, signatureContext, sessionKey, content) {
		var offset = 0;
		var response;
		while (offset != content.length) {
			var blockSize = ((content.length - offset > PlugupSAM.MAX_SIGNATURE_BLOCK_LENGTH) ? PlugupSAM.MAX_SIGNATURE_BLOCK_LENGTH : content.length - offset);
			var isLast = ((offset + blockSize) == content.length);
			response = this._sign(samKeysetVersion, samKeysetId, type, (isLast ? toLast : false), iv, signatureContext, sessionKey, content.bytes(offset, blockSize));
			if (!isLast) {
				iv = response['iv'];
				signatureContext = response['signatureContext'];
			}
			offset += blockSize;
		}
		return response;
	},

    _sign : function(samKeysetVersion, samKeysetId, type, last, iv, signatureContext, sessionKey, content) {
		if (!(sessionKey instanceof ByteString)) {
			throw "Invalid session key for sign";
		}
		var data = Convert.toHexByte(samKeysetVersion) + Convert.toHexByte(samKeysetId);
		data += sessionKey.toString(HEX);
		if (typeof iv == 'undefined') {
			iv = new ByteString("0000000000000000", HEX);
		} 
		if (typeof signatureContext == 'undefined') {
			signatureContext = new ByteString("000000000000000000", HEX);
		}
		data += iv.toString(HEX);
		data += signatureContext.toString(HEX);
		data += content.toString(HEX);
		var response = this.card.sendApdu(0xD0, 0x74, (last ? 0x80 : 0x00), type, new ByteString(data, HEX), [0x9000]);
		if (last) {
			return response;
		}
		var result = {};
		result['iv'] = response.bytes(0, 8);
		result['signatureContext'] = response.bytes(8);	
		return result;
	},

	cipherEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._cipherBlocks(samKeysetVersion, samKeysetId, 0x10, undefined, sessionKey, content);
	},

	cipherDek : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._cipherBlocks(samKeysetVersion, samKeysetId, 0x20, undefined, sessionKey, content);
	},

	decipherRenc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
		return this._cipherBlocks(samKeysetVersion, samKeysetId, 0x30, undefined, sessionKey, content);
	},

	_cipherBlocks : function(samKeysetVersion, samKeysetId, type, iv, sessionKey, content) {
		var offset = 0;
		var response = new ByteString("", HEX);
		if (content.length == 0) {
			// Valid use case when padding
			return this._cipher(samKeysetVersion, samKeysetId, type, true, iv, undefined, sessionKey, content);
		}
		var cipherContext = undefined;
		while (offset != content.length) {
			var blockSize = ((content.length - offset > PlugupSAM.MAX_CIPHER_BLOCK_LENGTH) ? PlugupSAM.MAX_CIPHER_BLOCK_LENGTH : content.length - offset);
			var isLast = ((offset + blockSize) == content.length);
			var result = this._cipher(samKeysetVersion, samKeysetId, type, isLast, iv, cipherContext, sessionKey, content.bytes(offset, blockSize));			
			if (!isLast) {
				iv = result['iv'];
				cipherContext = result['cipherContext'];
				response = response.concat(result['data']);
			}
			else {
				response = response.concat(result);
			}
			offset += blockSize;
		}
		return response;
	},

	_cipher : function(samKeysetVersion, samKeysetId, type, last, iv, cipherContext, sessionKey, content) {
		if (!(sessionKey instanceof ByteString)) {
			throw "Invalid session key for cipher";
		}		
		var data = Convert.toHexByte(samKeysetVersion) + Convert.toHexByte(samKeysetId);
		data += sessionKey.toString(HEX);
		if (typeof iv == 'undefined') {
			iv = new ByteString("0000000000000000", HEX);
		} 
		if (typeof cipherContext == 'undefined') {
			cipherContext = new ByteString("000000000000000000", HEX);
		}		
		data += iv.toString(HEX);
		data += cipherContext.toString(HEX);
		data += content.toString(HEX);
		var response = this.card.sendApdu(0xD0, 0x72, (last ? 0x80 : 0x00), type, new ByteString(data, HEX), [0x9000]);
		if (last) {
			return response;
		}
		var result = {};
		result['iv'] = response.bytes(0, 8);
		result['cipherContext'] = response.bytes(8, 9);	
		result['data'] = response.bytes(17);
		return result;
	}
 

});

