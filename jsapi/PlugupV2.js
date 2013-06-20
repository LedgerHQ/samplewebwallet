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

var PlugupV2 = Class.create({
	/**@lends PlugupV2.prototype */
	
	/**
	 * @class Communication with Plugup V2 application over a {@link Card} - administrative commands
	 * @param {Object} @Card implementing the Plugup V2 application
	 * @constructs
	 */
	initialize : function(card) {
		if (!(card instanceof Card) && !(card instanceof GPSecurityDomain)) {
			throw "Invalid card";
		}
		this.card = card;
	},
	
    select : function(fileId) {
        var data = new ByteString(Convert.toHexShort(fileId), HEX);
        return this.card.sendApdu(0x80, 0xA4, 0x00, 0x00, data, [0x9000]);	
    },

    getDeviceInfos : function() {
	var data = this.card.sendApdu(0x80, 0xe6, 0x00, 0x00, 0x12, [0x9000]);
	var result = {};
	result['STSerial'] = data.bytes(0, 6);
	result['STPIN'] = data.bytes(6, 2);
	result['STDate'] = data.bytes(8, 2);
	result['appID'] = data.bytes(10, 4);
	result['appVersion'] = ((data.byteAt(14) << 8) | data.byteAt(15)) + "." + data.byteAt(16) + "." + data.byteAt(17);
	return result;
    },
    
    getSerialNumber : function() {
        return this.card.sendApdu(0x80, 0xE6, 0x00, 0x00, 0x12, [0x9000]);
    },
        
    readBinary : function(offset, length) {
        var size = length;
        var result = new ByteString("", ASCII);
        while (size > 0) { // can read more than the expected data when wrapped in SCP
                var block = (size > 255) ? 255 : size;
                var data = this.card.sendApdu(0x80, 0xB0, (offset >> 8), (offset & 0xff), block, [0x9000]);
                result = result.concat(data);
                // decrement with received data (max = àxEF on the card size)
                size -= data.length;
                offset += data.length;
        }
        return result;
    },
    
    
	
	
	updateBinary : function(offset, data) {
		if (!(data instanceof ByteString)) {
			throw "Invalid data";
		}
		var size = data.length;
		var inputOffset = 0;
		while (size != 0) {
			var block = (size > 239 ? 239 : size);
			this.card.sendApdu(0x80, 0xD6, (offset >> 8), (offset & 0xff), data.bytes(inputOffset, block), [0x9000]);
			offset += block;
			inputOffset += block;
			size -= block;
		}			
	},
	
	computeHMACSHA1 : function(keyId, data, hotpdigits, useCounter, diversifier1, diversifier2) {
		var workData = new ByteString("", HEX);
		var p2 = 0x00;
		if (typeof diversifier1 != "undefined") {
			if (!(diversifier1 instanceof ByteString)) {
				throw "Invalid diversifier 1";
			}
			if (diversifier1.length != 16) {
				throw "Invalid diversifier 1 length";
			}
			workData = workData.concat(diversifier1);
			p2 = 0x01;
		}
		if (typeof diversifier2 != "undefined") {
			if (typeof diversifier1 == "undefined") {
				throw "Diversifier 1 must be specified";
			}
			if (!(diversifier2 instanceof ByteString)) {
				throw "Invalid diversifier 2";
			}
			if (diversifier2.length != 16) {
				throw "Invalid diversifier 2 length";
			}
			workData = workData.concat(diversifier2);
			p2 = 0x02;
		}
		if (typeof hotpdigits != "undefined") {
			switch(hotpdigits) {
				case 6:
					p2 |= 0x10;
					break;
				case 7:
					p2 |= 0x20;
					break;
				case 8:
					p2 |= 0x40;
					break;
				default:
					throw "Invalid size of HOTP digits";
			}
			if (useCounter) {
				p2 |= 0x80;
			}
		}

		workData = workData.concat(data);

		return this.card.sendApdu(0xD0, 0x22, keyId, p2, workData, [0x9000]);
	},

	exportTransientKeyset : function(keysetVersion, keysetId) {
		return this.card.sendApdu(0xD0, 0xA0, keysetVersion, keysetId, 0x00, [0x9000]);
	},

	importTransientKeyset : function(keysetVersion, keysetId, blob) {
		return this.card.sendApdu(0xD0, 0xA2, keysetVersion, keysetId, blob, [0x9000]);
	},

	encrypt : function(keysetVersion, keysetId, cbc, data, iv, diversifier1, diversifier2) {
		return this._encryptDecrypt(0x01, keysetVersion, keysetId, cbc, data, iv, diversifier1, diversifier2);	
	},

    decrypt : function(keysetVersion, keysetId, cbc, data, iv, diversifier1, diversifier2) {
        return this._encryptDecrypt(0x02, keysetVersion, keysetId, cbc, data, iv, diversifier1, diversifier2);
    },

	_encryptDecrypt : function(p1, keysetVersion, keysetId, cbc, data, iv, diversifier1, diversifier2) {
                var workData = new ByteString(Convert.toHexByte(keysetVersion) + Convert.toHexByte(keysetId), HEX);
                var p2 = 0x00;
		if (cbc) {
			p2 |= 0x02;
			if (typeof iv != "undefined") {
				if (!(iv instanceof ByteString) || (iv.length != 8)) {
					throw "Invalid iv";
				}
			}
		}
		else {
			p2 |= 0x01;
			iv = undefined;
		}
		if (typeof iv == "undefined") {
			iv = new ByteString("0000000000000000", HEX);
		}
		workData = workData.concat(iv);
		if (typeof diversifier1 != "undefined") {
			if (!(diversifier1 instanceof ByteString)) {
					throw "Invalid diversifier 1";
			}
			if (diversifier1.length != 16) {
					throw "Invalid diversifier 1 length";
			}
			workData = workData.concat(diversifier1);
			if (typeof diversifier2 == "undefined") {
				p2 |= 0x04;
			}
		}
		if (typeof diversifier2 != "undefined") {
			if (typeof diversifier1 == "undefined") {
				throw "Diversifier 1 must be specified";
			}
			if (!(diversifier2 instanceof ByteString)) {
				throw "Invalid diversifier 2";
			}
			if (diversifier2.length != 16) {
				throw "Invalid diversifier 2 length";
			}
			workData = workData.concat(diversifier2);
			p2 |= 0x08;
        }
		if (!(data instanceof ByteString) || ((data.length % 8) != 0)) {
			throw "Invalid data";
		}
		workData = workData.concat(data);
		return this.card.sendApdu(0xD0, 0x20, p1, p2, workData, [0x9000]);
	},

	generateRandom : function(size) {
		return this.card.sendApdu(0xD0, 0x24, 0x00, 0x00, size, [0x9000]);
	}
	

	
});


