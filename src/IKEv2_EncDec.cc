/******************************************************************************
* Copyright (c) 2005, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
* Gabor Szalai
* Eszter Susanszky
******************************************************************************/
//
//  File:               IKEv2_EncDec.cc
//  Description:        
//  Rev:                R2A
//  Prodnr:             CNL 113 801
//  Reference:          http://tools.ietf.org/search/rfc4306
//
///////////////////////////////////////////////////////////////////////////////

#include "IKEv2_Types.hh"


namespace IKEv2__Types
{	
	void decode_payload(IKEv2__Payloads& payload, int payload_nr, TTCN_Buffer& ttcn_buffer, Next__Payload__Type& type);
	Next__Payload__Type get_type(const IKEv2__Payload& payload, const bool& is_last);
	
	INTEGER ef__IKEv2__decode(const OCTETSTRING& pl__stream, IKEv2__Message& pl__pdu)
	{
		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_decode(): Stream before decoding: ");
			pl__stream.log();
			TTCN_Logger::end_event();
		}
		
		TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
		TTCN_EncDec::clear_error();
		
		TTCN_Buffer ttcn_buffer(pl__stream);
		IKEv2__Payloads& payload_list = pl__pdu.payload__list();
		
		pl__pdu.header().decode(IKEv2__Header_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
		Next__Payload__Type next_payload_type = pl__pdu.header().next__payload__type();
		if(next_payload_type == Next__Payload__Type::No__Next__Payload)
		{
			pl__pdu.payload__list() = OMIT_VALUE;
		}
	
	  int payload_nr = 0;
	  while(next_payload_type != Next__Payload__Type::No__Next__Payload)
		{
			decode_payload(payload_list, payload_nr, ttcn_buffer, next_payload_type);
			payload_nr++;
		}

		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_decode(): Decoded @IKEv2_Types.IKEv2_Message: ");
			pl__pdu.log();
			TTCN_Logger::end_event();
		}
		
		if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
			if (ttcn_buffer.get_pos() < ttcn_buffer.get_len()-1 && TTCN_Logger::log_this_event(TTCN_WARNING)) {
				ttcn_buffer.cut();
				OCTETSTRING remaining_stream;
				ttcn_buffer.get_string(remaining_stream);
				TTCN_Logger::begin_event(TTCN_WARNING);
				TTCN_Logger::log_event_str("ef_IKEv2_decode(): Warning: Data remained at the end of the stream after successful decoding: ");
				remaining_stream.log();
				TTCN_Logger::end_event();
			}	
		  return 0;
    }
    return 1;
	}
	
	void decode_payload(IKEv2__Payloads& payload_list, int payload_nr, TTCN_Buffer& ttcn_buffer, Next__Payload__Type& type){
		
		switch (type)
		{
			case Next__Payload__Type::Security__Association: 
				payload_list[payload_nr].security__association__payload().decode(Security__Association__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW); 
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
        type = payload_list[payload_nr].security__association__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Key__Exchange:
				payload_list[payload_nr].key__exchange__payload().decode(Key__Exchange__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].key__exchange__payload().payload__header().next__payload__type(); 
				break;
			case Next__Payload__Type::Id__Initiator:
				payload_list[payload_nr].id__initiator__payload().decode(Identification__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].id__initiator__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Id__Responder:
				payload_list[payload_nr].id__responder__payload().decode(Identification__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].id__responder__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Certificate:
				payload_list[payload_nr].certificate__payload().decode(Certificate__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].certificate__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Certificate__Request:
				payload_list[payload_nr].certificate__request__payload().decode(Certificate__Request__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].certificate__request__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Authentication:
				payload_list[payload_nr].authentication__payload().decode(Authentication__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].authentication__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Nonce:
				payload_list[payload_nr].nonce__payload().decode(Nonce__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].nonce__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Notify:
				payload_list[payload_nr].notify__payload().decode(Notify__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].notify__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Delete:
				payload_list[payload_nr].delete__payload().decode(Delete__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].delete__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Vendor__Id:
				payload_list[payload_nr].vendor__id__payload().decode(Vendor__ID__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				type = payload_list[payload_nr].vendor__id__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Traffic__Selector__Initiator:
				payload_list[payload_nr].ts__initiator__payload().decode(Traffic__Selector__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].ts__initiator__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Traffic__Selector__Responder:
				payload_list[payload_nr].ts__responder__payload().decode(Traffic__Selector__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].ts__responder__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Configuration:
				payload_list[payload_nr].configuration__payload().decode(Configuration__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].configuration__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::EAP:
				payload_list[payload_nr].eap__payload().decode(EAP__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = payload_list[payload_nr].eap__payload().payload__header().next__payload__type();
				break;
			case Next__Payload__Type::Encrypted:
				payload_list[payload_nr].encrypted__payload().decode(Encrypted__Payload_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
				if (TTCN_EncDec::get_last_error_type() != TTCN_EncDec::ET_NONE) {
          type = Next__Payload__Type::No__Next__Payload;
          return;
        }
				type = Next__Payload__Type::No__Next__Payload;
				break;
			default: 
        TTCN_warning("Internal error: Invalid selector in a specific value when decoding @IKEv2_Types.IKEv2_Payload.");
          type = Next__Payload__Type::No__Next__Payload;
  		}
	}

	
	INTEGER ef__IKEv2__Payloads__decode(const OCTETSTRING& pl__stream, const Next__Payload__Type& pl__type, IKEv2__Payloads& pl__payload__list)
	{
		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC))
		{
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_Payload_decode(): Stream before decoding: ");
			pl__stream.log();
			TTCN_Logger::end_event();
		}
		TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
		TTCN_EncDec::clear_error();
		
		TTCN_Buffer ttcn_buffer(pl__stream);
		
		Next__Payload__Type next_payload_type = pl__type;
	
	  int payload_nr = 0;
	  while(next_payload_type != Next__Payload__Type::No__Next__Payload)
		{
/*			if(next_payload_type == Next__Payload__Type::Encrypted) 
			{
				TTCN_warning("An Encrypted Payload can not contain other Encrypted Payloads");
        break;
			}*/
			decode_payload(pl__payload__list, payload_nr, ttcn_buffer, next_payload_type);
			payload_nr++;
		}
		
		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC))
		{
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_Payload_Decode(): Decoding @IKEv2_Types.IKEv2_Payload: ");
			pl__payload__list.log();
			TTCN_Logger::end_event();
		}		
		
		if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE)
		{
			if (ttcn_buffer.get_pos() < ttcn_buffer.get_len()-1 && TTCN_Logger::log_this_event(TTCN_WARNING)) {
				ttcn_buffer.cut();
				OCTETSTRING remaining_stream;
				ttcn_buffer.get_string(remaining_stream);
				TTCN_Logger::begin_event(TTCN_WARNING);
				TTCN_Logger::log_event_str("ef_IKE_v2_decode(): Warning: Data remained at the end of the stream after successful decoding: ");
				remaining_stream.log();
				TTCN_Logger::end_event();
			}
      return 0;
		}
    return 1;
	}
	
	void ef__IKEv2__encode(const IKEv2__Message& pl__pdu, const BOOLEAN& pl__set__payload__type, OCTETSTRING& pl__stream)
	{
		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_encode(): Encoding @IKEv2_Types.IKEv2_Message: ");
			pl__pdu.log();
			TTCN_Logger::end_event();
		}
		TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
		TTCN_Buffer ttcn_buffer;

		IKEv2__Message pdu = pl__pdu;
		
		if(pl__set__payload__type)
		{
			if(pdu.payload__list().ispresent() && (pdu.payload__list()().lengthof() != 0))
			{
				bool is_last = false;
				IKEv2__Payload next_payload = pdu.payload__list()()[0];
				pdu.header().next__payload__type() = get_type(next_payload, is_last);
			
				int nr_of_payloads = pdu.payload__list()().lengthof();
			
				for(int i = 0; i < nr_of_payloads; i++)
				{
					if(i == (nr_of_payloads - 1))
					{
						is_last = true;
					} else {
						next_payload = pdu.payload__list()()[i+1];
					}
			
					switch(pdu.payload__list()()[i].get_selection())
					{
						case IKEv2__Payload::ALT_security__association__payload:
							pdu.payload__list()()[i].security__association__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_key__exchange__payload:
							pdu.payload__list()()[i].key__exchange__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_id__initiator__payload:
							pdu.payload__list()()[i].id__initiator__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_id__responder__payload:
							pdu.payload__list()()[i].id__responder__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_certificate__payload:
							pdu.payload__list()()[i].certificate__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_certificate__request__payload:
							pdu.payload__list()()[i].certificate__request__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_authentication__payload:
							pdu.payload__list()()[i].authentication__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_nonce__payload:
							pdu.payload__list()()[i].nonce__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_notify__payload:
							pdu.payload__list()()[i].notify__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_delete__payload:
							pdu.payload__list()()[i].delete__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_vendor__id__payload:
							pdu.payload__list()()[i].vendor__id__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_ts__initiator__payload:
							pdu.payload__list()()[i].ts__initiator__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_ts__responder__payload:
							pdu.payload__list()()[i].ts__responder__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_encrypted__payload: break;
						case IKEv2__Payload::ALT_configuration__payload:
							pdu.payload__list()()[i].configuration__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						case IKEv2__Payload::ALT_eap__payload:
							pdu.payload__list()()[i].eap__payload().payload__header().next__payload__type() = get_type(next_payload, is_last); break;
						default: TTCN_error("Internal error: Invalid selector in a specific value when performing get_selection() operation on a template of union type @IKEv2_Types.IKEv2_Payload.");
					}
				}
			} else {
				pdu.header().next__payload__type() = Next__Payload__Type::No__Next__Payload;
			}
			
			pdu.encode(IKEv2__Message_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
			
		} else {
			pl__pdu.encode(IKEv2__Message_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
		}

		ttcn_buffer.get_string(pl__stream);

		if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
			TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
			TTCN_Logger::log_event_str("ef_IKEv2_encode(): Stream after encoding: ");
			pl__stream.log();
			TTCN_Logger::end_event();
		}
	}
	
	Next__Payload__Type get_type(const IKEv2__Payload& payload, const bool& is_last){
		if(is_last == false)
		{
			switch(payload.get_selection())
			{
				case IKEv2__Payload::ALT_security__association__payload: return Next__Payload__Type::Security__Association;
				case IKEv2__Payload::ALT_key__exchange__payload: return Next__Payload__Type::Key__Exchange;
				case IKEv2__Payload::ALT_id__initiator__payload: return Next__Payload__Type::Id__Initiator;
				case IKEv2__Payload::ALT_id__responder__payload: return Next__Payload__Type::Id__Responder;
				case IKEv2__Payload::ALT_certificate__payload: return Next__Payload__Type::Certificate;
				case IKEv2__Payload::ALT_certificate__request__payload: return Next__Payload__Type::Certificate__Request;
				case IKEv2__Payload::ALT_authentication__payload: return Next__Payload__Type::Authentication;
				case IKEv2__Payload::ALT_nonce__payload: return Next__Payload__Type::Nonce;
				case IKEv2__Payload::ALT_notify__payload: return Next__Payload__Type::Notify;
				case IKEv2__Payload::ALT_delete__payload: return Next__Payload__Type::Delete;
				case IKEv2__Payload::ALT_vendor__id__payload: return Next__Payload__Type::Vendor__Id;
				case IKEv2__Payload::ALT_ts__initiator__payload: return Next__Payload__Type::Traffic__Selector__Initiator;
				case IKEv2__Payload::ALT_ts__responder__payload: return Next__Payload__Type::Traffic__Selector__Responder;
				case IKEv2__Payload::ALT_encrypted__payload: return Next__Payload__Type::Encrypted;
				case IKEv2__Payload::ALT_configuration__payload: return Next__Payload__Type::Configuration;
				case IKEv2__Payload::ALT_eap__payload: return Next__Payload__Type::EAP;
				default: TTCN_error("Internal error: Invalid selector in a specific value when performing get_type(next_payload, is_last) operation on a template of union type @IKEv2_Types.IKEv2_Payload.");
			}
		} else {
			return Next__Payload__Type::No__Next__Payload;
		}
	}
}
