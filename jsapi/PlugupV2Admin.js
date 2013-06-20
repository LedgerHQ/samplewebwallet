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

var PlugupV2Admin = Class.extend(PlugupV2, {
	/**@lends PlugupV2Admin.prototype */
	
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
	
	createDF : function(fileId, accessCreateEF, accessCreateDF, accessDeleteSelf) {
		if (typeof accessCreateEF == "undefined") {
			accessCreateEF = PlugupV2Admin.ACCESS_ALWAYS;
		}
		if (typeof accessCreateDF == "undefined") {
			accessCreateDF = PlugupV2Admin.ACCESS_ALWAYS;
		}
		if (typeof accessDeleteSelf == "undefined") {
			accessDeleteSelf = PlugupV2Admin.ACCESS_ALWAYS;
		}
		var data = "6208820232218302" + Convert.toHexShort(fileId) + 
				   "8C0400" + Convert.toHexByte(accessDeleteSelf) + Convert.toHexByte(accessCreateDF) + 
				   Convert.toHexByte(accessCreateEF);
		return this.card.sendApdu(0x80, 0xE0, 0x00, 0x00, new ByteString(data, HEX), [0x9000]);
	},
	
	createEF : function(fileId, size, accessRead, accessUpdate, accessDelete, encrypted, counter) {
		if (typeof accessRead == "undefined") {
			accessRead = PlugupV2Admin.ACCESS_ALWAYS;
		}
		if (typeof accessUpdate == "undefined") {
			accessUpdate = PlugupV2Admin.ACCESS_ALWAYS;
		}
		if (typeof accessDelete == "undefined") {
			accessDelete = PlugupV2Admin.ACCESS_ALWAYS;
		}
		var data = "820201218302" + Convert.toHexShort(fileId) + 
				   "8102" + Convert.toHexShort(size) +
				   "8C0600" + Convert.toHexByte(accessDelete) + "0000" + 
				   Convert.toHexByte(accessUpdate) + Convert.toHexByte(accessRead);
		if (encrypted) {
			data += "860101";
		}
		if (counter) {
			data += "870101";
		}
		data = "62" + Convert.toHexByte(data.length / 2) + data;
		return this.card.sendApdu(0x80, 0xE0, 0x00, 0x00, new ByteString(data, HEX), [0x9000]);
	},

        deleteFile: function(fileId) {
                var data = new ByteString(Convert.toHexShort(fileId), HEX);
                return this.card.sendApdu(0x80, 0xE4, 0x00, 0x00, data, [0x9000]);
        },

	/**
	 * Return the current life cycle status of the application 
	 * @returns {Number} life cycle status
	 */	
	getStatus: function() {
		return this.card.sendApdu(0x80, 0xF2, 0x40, 0x00, 0x08, [0x9000]);
	},
	
	/**
	 * Set the application life cycle status to PERSONALIZED
	 */	
	setPersonalized: function() {
		return this.card.sendApdu(0x80, 0xF0, 0x40, 0x0F, 0x00, [0x9000]);
	},
	
	/**
	 * Set the application life cycle status to LOCKED	
	 */	
	setLocked: function() {
		return this.card.sendApdu(0x80, 0xF0, 0x40, 0x83, 0x00, [0x9000]);
	},
	
	/**
	 * Set the application life cycle status to TERMINATED	
	 */	
	setTerminated: function() {
		return this.card.sendApdu(0x80, 0xF0, 0x40, 0x7F, 0x00, [0x9000]);
	},

	useAsKeyboardInput : function() {
		return this.card.sendApdu(0xD0, 0x32, 0x00, 0x00, 0x00, [0x9000]);
	},

	setKeyboardBootActivated : function(activated) {
		return this.card.sendApdu(0xD0, 0x32, (activated ? 0x02 : 0x01), 0x00, 0x00, [0x9000]);
	}	
	
});

PlugupV2Admin.ACCESS_ALWAYS = 0x00;
PlugupV2Admin.ACCESS_FIRST_KEYSET = 0x01;
PlugupV2Admin.ACCESS_LAST_KEYSET = 0xfe;
PlugupV2Admin.ACCESS_NEVER = 0xFF;

PlugupV2Admin.KEY_ROLE_GP = 0x01;
PlugupV2Admin.KEY_ROLE_GP_AUTH = 0x02;
PlugupV2Admin.KEY_ROLE_HOTP_OATH = 0x03;
PlugupV2Admin.KEY_ROLE_HOTP_OATH_VERIFY = 0x04;
PlugupV2Admin.KEY_ROLE_PROPRIETARY_OTP = 0x05;
PlugupV2Admin.KEY_ROLE_ENCRYPT = 0x06;
PlugupV2Admin.KEY_ROLE_DECRYPT = 0x07;
PlugupV2Admin.KEY_ROLE_ENCRYPT_DECRYPT = 0x08;
PlugupV2Admin.KEY_ROLE_SAM_CONTEXT = 0x09;
PlugupV2Admin.KEY_ROLE_SAM_GP_USABLE = 0x0A;
PlugupV2Admin.KEY_ROLE_SAM_PROVISIONABLE_1_DIV = 0x0B;
PlugupV2Admin.KEY_ROLE_SAM_PROVISIONABLE_2_DIV = 0x0C;
PlugupV2Admin.KEY_ROLE_SAM_CLEARTEXT_EXPORTABLE_1_DIV = 0x0D;
PlugupV2Admin.KEY_ROLE_SAM_CLEARTEXT_EXPORTABLE_2_DIV = 0x0E;
PlugupV2Admin.KEY_ROLE_TRANSIENT_IMPORT_EXPORT = 0x0F;


