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

var PlugupSAM = Class.create({
	/**@lends PlugupSAM.prototype */
	
	initialize : function() {
		throw "Abstract class";
	},

	diversifyGP : function(samKeysetVersion, samKeysetId, GPKeysetId, flags, sequenceCounter, diversifier1, diversifier2) {
	},

	deriveCleartext : function(targetKeysetId, diversifier1, diversifier2) {
	},

	preparePutKey : function(samKeysetVersion, samKeysetId, targetKeysetId, sessionKey, diversifier1, diversifier2) {
	},

	signEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
	},

	signCmacUpdate : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
	},

	signCmacFinal : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
	},

    signCmac : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
    },

    signRmacCommand : function(samKeysetVersion, samKeysetId, iv, sessionKey, content) {
    },

	signRmacResponse : function(samKeysetVersion, samKeysetId, iv, signatureContext, sessionKey, content) {
	},

	cipherEnc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
	},

	cipherDek : function(samKeysetVersion, samKeysetId, sessionKey, content) {
	},

	decipherRenc : function(samKeysetVersion, samKeysetId, sessionKey, content) {
	}, 

});

PlugupSAM.OPTION_GENERATE_DEK = 0x04;
PlugupSAM.OPTION_GENERATE_RMAC = 0x08;
PlugupSAM.OPTION_GENERATE_RENC = 0x10;

PlugupSAM.MAX_SIGNATURE_BLOCK_LENGTH = 0xD4;
PlugupSAM.MAX_CIPHER_BLOCK_LENGTH = 0xD4;

