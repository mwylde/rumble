use nom;
use nom::*;

fn rest(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    Ok((&[][..], i.to_vec()))
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct L2capPacket {
    _packet_len: u16,
    _length: u16,
    _channel_id: u16,
    _payload: Vec<u8>,
}

impl L2capPacket {
    pub fn get_length(&self) -> u16 {
        self._length
    }

    pub fn get_channel_id(&self) -> u16 {
        self._channel_id
    }

    pub fn get_payload(&self) -> &[u8] {
        &self._payload
    }

    pub fn parse(_i0: &[u8], _packet_len: u16) -> IResult<&[u8], L2capPacket> {
        let (_i1, _length) = try_parse!(_i0, le_u16);
        let (_i2, _channel_id) = try_parse!(_i1, le_u16);
        let (_i3, _payload) = try_parse!(_i2, count!(le_u8, (_packet_len - 0x4) as usize));
        Ok((_i3, L2capPacket { _packet_len, _length, _channel_id, _payload }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct HciEvent {
    _event_code: u8,
    _parameter_length: u8,
    _data: Vec<u8>,
    _event: HciEvent_Event,
}

impl HciEvent {
    pub fn get_event(&self) -> &HciEvent_Event {
        &self._event
    }

    pub fn parse(_i0: &[u8], _type: u8) -> IResult<&[u8], HciEvent> {
        if _type != 0x4 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _event_code) = try_parse!(_i0, le_u8);
        let (_i2, _parameter_length) = try_parse!(_i1, le_u8);
        let (_i3, _data) = try_parse!(_i2, count!(le_u8, _parameter_length as usize));
        let (_, _event) = try_parse!(&_i2[.._parameter_length as usize], alt!(
            call!(DisconnectionComplete::parse, _event_code) => {|v| HciEvent_Event::DisconnectionComplete(v)} |
            call!(CommandComplete::parse, _event_code) => {|v| HciEvent_Event::CommandComplete(v)} |
            call!(LeMetaEvent::parse, _event_code) => {|v| HciEvent_Event::LeMetaEvent(v)} |
            call!(UnknownEvent::parse, _event_code) => {|v| HciEvent_Event::UnknownEvent(v)}
    ));
        Ok((_i3, HciEvent { _event_code, _parameter_length, _data, _event }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct UnknownEvent {
    _event_code: u8,
    _data: Vec<u8>,
}

impl UnknownEvent {
    pub fn get_event_code(&self) -> u8 {
        self._event_code
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _event_code: u8) -> IResult<&[u8], UnknownEvent> {
        let (_i1, _data) = try_parse!(_i0, rest);
        Ok((_i1, UnknownEvent { _event_code, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct DisconnectionComplete {
    _status: ResponseStatus,
    _connection_handle: u16,
    _reason: u8,
}

impl DisconnectionComplete {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_handle(&self) -> u16 {
        self._connection_handle
    }

    pub fn get_reason(&self) -> u8 {
        self._reason
    }

    pub fn parse(_i0: &[u8], _event_code: u8) -> IResult<&[u8], DisconnectionComplete> {
        if _event_code != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _connection_handle) = try_parse!(_i1, le_u16);
        let (_i3, _reason) = try_parse!(_i2, le_u8);
        Ok((_i3, DisconnectionComplete { _status, _connection_handle, _reason }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct CommandComplete {
    _num_packets: u8,
    _opcode: u16,
    _response: CommandComplete_Response,
}

impl CommandComplete {
    pub fn get_num_packets(&self) -> u8 {
        self._num_packets
    }

    pub fn get_response(&self) -> &CommandComplete_Response {
        &self._response
    }

    pub fn parse(_i0: &[u8], _event_code: u8) -> IResult<&[u8], CommandComplete> {
        if _event_code != 0xE {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _num_packets) = try_parse!(_i0, le_u8);
        let (_i2, _opcode) = try_parse!(_i1, le_u16);
        let _ogf: u8 = (_opcode >> 0xA) as u8;
        let _ocf: u16 = (_opcode & 0x400 - 0x1) as u16;
        let (_i3, _response) = try_parse!(_i2, alt!(
            call!(NoAssociatedCommand::parse, _ogf, _ocf) => {|v| CommandComplete_Response::NoAssociatedCommand(v)} |
            call!(ResetResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::Reset(v)} |
            call!(SetEventFilterResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::SetEventFilter(v)} |
            call!(FlushResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::Flush(v)} |
            call!(WriteLocalNameResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteLocalName(v)} |
            call!(ReadLocalNameResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadLocalName(v)} |
            call!(ReadConnectionAcceptTimeoutResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadConnectionAcceptTimeout(v)} |
            call!(WriteConnectionAcceptTimeoutResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteConnectionAcceptTimeout(v)} |
            call!(ReadPageTimeoutResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadPageTimeout(v)} |
            call!(WritePageTimeoutResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WritePageTimeout(v)} |
            call!(ReadScanEnableResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadScanEnable(v)} |
            call!(WriteScanEnableResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteScanEnable(v)} |
            call!(ReadPageScanActivityResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadPageScanActivity(v)} |
            call!(WritePageScanActivityResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WritePageScanActivity(v)} |
            call!(ReadInquiryScanActivityResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadInquiryScanActivity(v)} |
            call!(WriteInquiryScanActivityResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteInquiryScanActivity(v)} |
            call!(ReadExtendedInquiryResponseResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadExtendedInquiryResponse(v)} |
            call!(WriteExtendedInquiryResponseResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteExtendedInquiryResponse(v)} |
            call!(ReadLeHostSupportResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::ReadLeHostSupport(v)} |
            call!(WriteLeHostSupportResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::WriteLeHostSupport(v)} |
            call!(LeSetEventMask::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetEventMask(v)} |
            call!(LeSetEventMaskResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetEventMaskResponse(v)} |
            call!(LeReadBufferSizeResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeReadBufferSize(v)} |
            call!(LeReadLocalSupportedFeaturesResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeReadLocalSupportedFeatures(v)} |
            call!(LeSetRandomAddressCommandResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetRandomAddressCommand(v)} |
            call!(LeSetAdvertisingParametersResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetAdvertisingParameters(v)} |
            call!(LeSetAdvertisingDataResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LESetAdvertisingData(v)} |
            call!(LeSetScanParametersResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetScanParameters(v)} |
            call!(LeSetScanEnableResponse::parse, _ogf, _ocf) => {|v| CommandComplete_Response::LeSetScanEnable(v)} |
            call!(UnknownCommand::parse, _ogf, _ocf) => {|v| CommandComplete_Response::UnknownCommand(v)}
    ));
        Ok((_i3, CommandComplete { _num_packets, _opcode, _response }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct NoAssociatedCommand {
    _ogf: u8,
}

impl NoAssociatedCommand {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], NoAssociatedCommand> {
        if _ocf != 0x0 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, NoAssociatedCommand { _ogf }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct UnknownCommand {
    _ogf: u8,
    _ocf: u16,
    _status: ResponseStatus,
    _data: Vec<u8>,
}

impl UnknownCommand {
    pub fn get_ogf(&self) -> u8 {
        self._ogf
    }

    pub fn get_ocf(&self) -> u16 {
        self._ocf
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], UnknownCommand> {
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _data) = try_parse!(_i1, rest);
        Ok((_i2, UnknownCommand { _ogf, _ocf, _status, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct EndThing2 {
}

impl EndThing2 {
    pub fn parse(_i0: &[u8]) -> IResult<&[u8], EndThing2> {
        Ok((_i0, EndThing2 {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct HciCommand {
    _opcode: u16,
    _length: u8,
    _data: Vec<u8>,
    _command: HciCommand_Command,
}

impl HciCommand {
    pub fn get_command(&self) -> &HciCommand_Command {
        &self._command
    }

    pub fn parse(_i0: &[u8], _type: u8) -> IResult<&[u8], HciCommand> {
        if _type != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _opcode) = try_parse!(_i0, le_u16);
        let _ogf: u8 = (_opcode >> 0xA) as u8;
        let _ocf: u16 = (_opcode & 0x400 - 0x1) as u16;
        let (_i2, _length) = try_parse!(_i1, le_u8);
        let (_i3, _data) = try_parse!(_i2, count!(le_u8, _length as usize));
        let (_, _command) = try_parse!(&_i2[.._length as usize], alt!(
            call!(Reset::parse, _ogf, _ocf) => {|v| HciCommand_Command::Reset(v)} |
            call!(SetEventFilter::parse, _ogf, _ocf) => {|v| HciCommand_Command::SetEventFilter(v)} |
            call!(Flush::parse, _ogf, _ocf) => {|v| HciCommand_Command::Flush(v)} |
            call!(WriteLocalName::parse, _ogf, _ocf) => {|v| HciCommand_Command::WriteLocalName(v)} |
            call!(ReadLocalName::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadLocalName(v)} |
            call!(ReadConnectionAcceptTimeout::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadConnectionAcceptTimeout(v)} |
            call!(WriteConnectionAcceptTimeout::parse, _ogf, _ocf) => {|v| HciCommand_Command::WriteConnectionAcceptTimeout(v)} |
            call!(ReadPageTimeout::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadPageTimeout(v)} |
            call!(WritePageTimeout::parse, _ogf, _ocf) => {|v| HciCommand_Command::WritePageTimeout(v)} |
            call!(ReadScanEnable::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadScanEnable(v)} |
            call!(WriteScanEnable::parse, _ogf, _ocf) => {|v| HciCommand_Command::WriteScanEnable(v)} |
            call!(ReadPageScanActivity::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadPageScanActivity(v)} |
            call!(WritePageScanActivity::parse, _ogf, _ocf) => {|v| HciCommand_Command::WritePageScanActivity(v)} |
            call!(ReadInquiryScanActivity::parse, _ogf, _ocf) => {|v| HciCommand_Command::ReadInquiryScanActivity(v)} |
            call!(WriteInquiryScanActivity::parse, _ogf, _ocf) => {|v| HciCommand_Command::WriteInquiryScanActivity(v)} |
            call!(LeSetAdvertisingData::parse, _ogf, _ocf) => {|v| HciCommand_Command::LESetAdvertisingData(v)} |
            call!(Unknown::parse, _ogf, _ocf) => {|v| HciCommand_Command::Unknown(v)}
    ));
        Ok((_i3, HciCommand { _opcode, _length, _data, _command }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ResponseStatus {
    _status_code: u8,
}

impl ResponseStatus {
    pub fn get_status_code(&self) -> u8 {
        self._status_code
    }

    pub fn parse(_i0: &[u8]) -> IResult<&[u8], ResponseStatus> {
        let (_i1, _status_code) = try_parse!(_i0, le_u8);
        Ok((_i1, ResponseStatus { _status_code }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Unknown {
    _ogf: u8,
    _ocf: u16,
}

impl Unknown {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], Unknown> {
        Ok((_i0, Unknown { _ogf, _ocf }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Reset {
}

impl Reset {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], Reset> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, Reset {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ResetResponse {
    _status: ResponseStatus,
}

impl ResetResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ResetResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, ResetResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct SetEventFilter {
    _filter_type: u8,
    _filter: SetEventFilter_Filter,
}

impl SetEventFilter {
    pub fn get_filter(&self) -> &SetEventFilter_Filter {
        &self._filter
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], SetEventFilter> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _filter_type) = try_parse!(_i0, le_u8);
        let (_i2, _filter) = try_parse!(_i1, alt!(
            call!(ClearAllFilter::parse, _filter_type) => {|v| SetEventFilter_Filter::ClearAllFilter(v)} |
            call!(InquiryResult::parse, _filter_type) => {|v| SetEventFilter_Filter::InquiryResult(v)} |
            call!(ConnectionSetup::parse, _filter_type) => {|v| SetEventFilter_Filter::ConnectionSetup(v)}
    ));
        Ok((_i2, SetEventFilter { _filter_type, _filter }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct SetEventFilterResponse {
    _status: ResponseStatus,
}

impl SetEventFilterResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], SetEventFilterResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, SetEventFilterResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct InquiryResult {
    _condition: FilterCondition,
}

impl InquiryResult {
    pub fn get_condition(&self) -> &FilterCondition {
        &self._condition
    }

    pub fn parse(_i0: &[u8], _filter_type: u8) -> IResult<&[u8], InquiryResult> {
        if _filter_type != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _condition) = try_parse!(_i0, FilterCondition::parse);
        Ok((_i1, InquiryResult { _condition }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ConnectionSetup {
    _condition: FilterCondition,
    _auto_accept: u8,
}

impl ConnectionSetup {
    pub fn get_condition(&self) -> &FilterCondition {
        &self._condition
    }

    pub fn get_auto_accept(&self) -> u8 {
        self._auto_accept
    }

    pub fn parse(_i0: &[u8], _filter_type: u8) -> IResult<&[u8], ConnectionSetup> {
        if _filter_type != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _condition) = try_parse!(_i0, FilterCondition::parse);
        let (_i2, _auto_accept) = try_parse!(_i1, le_u8);
        Ok((_i2, ConnectionSetup { _condition, _auto_accept }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FilterCondition {
    _condition_type: u8,
    _value: FilterCondition_Value,
}

impl FilterCondition {
    pub fn get_value(&self) -> &FilterCondition_Value {
        &self._value
    }

    pub fn parse(_i0: &[u8]) -> IResult<&[u8], FilterCondition> {
        let (_i1, _condition_type) = try_parse!(_i0, le_u8);
        let (_i2, _value) = try_parse!(_i1, alt!(
            call!(AllDevices::parse, _condition_type) => {|v| FilterCondition_Value::AllDevices(v)} |
            call!(MatchClass::parse, _condition_type) => {|v| FilterCondition_Value::MatchClass(v)} |
            call!(MatchAddress::parse, _condition_type) => {|v| FilterCondition_Value::MatchAddress(v)}
    ));
        Ok((_i2, FilterCondition { _condition_type, _value }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ClearAllFilter {
}

impl ClearAllFilter {
    pub fn parse(_i0: &[u8], _filter_type: u8) -> IResult<&[u8], ClearAllFilter> {
        if _filter_type != 0x0 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ClearAllFilter {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct AllDevices {
}

impl AllDevices {
    pub fn parse(_i0: &[u8], _condition_type: u8) -> IResult<&[u8], AllDevices> {
        if _condition_type != 0x0 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, AllDevices {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct MatchClass {
    _class_of_device: Vec<u8>,
    _class_of_device_mask: Vec<u8>,
}

impl MatchClass {
    pub fn get_class_of_device(&self) -> &[u8] {
        &self._class_of_device
    }

    pub fn get_class_of_device_mask(&self) -> &[u8] {
        &self._class_of_device_mask
    }

    pub fn parse(_i0: &[u8], _condition_type: u8) -> IResult<&[u8], MatchClass> {
        if _condition_type != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _class_of_device) = try_parse!(_i0, count!(le_u8, 3));
        let (_i2, _class_of_device_mask) = try_parse!(_i1, count!(le_u8, 3));
        Ok((_i2, MatchClass { _class_of_device, _class_of_device_mask }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct MatchAddress {
    _address: Vec<u8>,
}

impl MatchAddress {
    pub fn get_address(&self) -> &[u8] {
        &self._address
    }

    pub fn parse(_i0: &[u8], _condition_type: u8) -> IResult<&[u8], MatchAddress> {
        if _condition_type != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _address) = try_parse!(_i0, count!(le_u8, 6));
        Ok((_i1, MatchAddress { _address }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Flush {
    _connection_handle: u16,
}

impl Flush {
    pub fn get_connection_handle(&self) -> u16 {
        self._connection_handle
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], Flush> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _connection_handle) = try_parse!(_i0, le_u16);
        Ok((_i1, Flush { _connection_handle }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FlushResponse {
    _status: ResponseStatus,
    _connection_handle: u16,
}

impl FlushResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_handle(&self) -> u16 {
        self._connection_handle
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], FlushResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _connection_handle) = try_parse!(_i1, le_u16);
        Ok((_i2, FlushResponse { _status, _connection_handle }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteLocalName {
    _local_name_buffer: Vec<u8>,
    _local_name: String,
}

impl WriteLocalName {
    pub fn get_local_name(&self) -> &String {
        &self._local_name
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteLocalName> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x13 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _local_name_buffer) = try_parse!(_i0, count!(le_u8, 248));
        let (_, _local_name) = try_parse!(&_i0[..248 as usize], map_res!(take_until!("\0"), |v: &[u8]| String::from_utf8(v.to_owned())));
        Ok((_i1, WriteLocalName { _local_name_buffer, _local_name }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteLocalNameResponse {
    _status: ResponseStatus,
}

impl WriteLocalNameResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteLocalNameResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x13 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteLocalNameResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadLocalName {
}

impl ReadLocalName {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadLocalName> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x14 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadLocalName {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadLocalNameResponse {
    _status: ResponseStatus,
    _local_name_buffer: Vec<u8>,
    _local_name: String,
}

impl ReadLocalNameResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_local_name(&self) -> &String {
        &self._local_name
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadLocalNameResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x14 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _local_name_buffer) = try_parse!(_i1, count!(le_u8, 248));
        let (_, _local_name) = try_parse!(&_i1[..248 as usize], map_res!(take_until!("\0"), |v: &[u8]| String::from_utf8(v.to_owned())));
        Ok((_i2, ReadLocalNameResponse { _status, _local_name_buffer, _local_name }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadConnectionAcceptTimeout {
}

impl ReadConnectionAcceptTimeout {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadConnectionAcceptTimeout> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x15 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadConnectionAcceptTimeout {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadConnectionAcceptTimeoutResponse {
    _status: ResponseStatus,
    _connection_accept_timeout: u16,
}

impl ReadConnectionAcceptTimeoutResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_accept_timeout(&self) -> u16 {
        self._connection_accept_timeout
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadConnectionAcceptTimeoutResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x15 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _connection_accept_timeout) = try_parse!(_i1, le_u16);
        Ok((_i2, ReadConnectionAcceptTimeoutResponse { _status, _connection_accept_timeout }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteConnectionAcceptTimeout {
    _connection_accept_timeout: u16,
}

impl WriteConnectionAcceptTimeout {
    pub fn get_connection_accept_timeout(&self) -> u16 {
        self._connection_accept_timeout
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteConnectionAcceptTimeout> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x16 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _connection_accept_timeout) = try_parse!(_i0, le_u16);
        Ok((_i1, WriteConnectionAcceptTimeout { _connection_accept_timeout }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteConnectionAcceptTimeoutResponse {
    _status: ResponseStatus,
}

impl WriteConnectionAcceptTimeoutResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteConnectionAcceptTimeoutResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x16 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteConnectionAcceptTimeoutResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadPageTimeout {
}

impl ReadPageTimeout {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadPageTimeout> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x17 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadPageTimeout {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadPageTimeoutResponse {
    _status: ResponseStatus,
    _page_timeout: u16,
}

impl ReadPageTimeoutResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_page_timeout(&self) -> u16 {
        self._page_timeout
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadPageTimeoutResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x17 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _page_timeout) = try_parse!(_i1, le_u16);
        Ok((_i2, ReadPageTimeoutResponse { _status, _page_timeout }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WritePageTimeout {
    _page_timeout: u16,
}

impl WritePageTimeout {
    pub fn get_page_timeout(&self) -> u16 {
        self._page_timeout
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WritePageTimeout> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x18 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _page_timeout) = try_parse!(_i0, le_u16);
        Ok((_i1, WritePageTimeout { _page_timeout }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WritePageTimeoutResponse {
    _status: ResponseStatus,
}

impl WritePageTimeoutResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WritePageTimeoutResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x18 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WritePageTimeoutResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadScanEnable {
}

impl ReadScanEnable {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadScanEnable> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x19 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadScanEnable {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadScanEnableResponse {
    _status: ResponseStatus,
    _scan_enable: u8,
}

impl ReadScanEnableResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_scan_enable(&self) -> u8 {
        self._scan_enable
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadScanEnableResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x19 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _scan_enable) = try_parse!(_i1, le_u8);
        Ok((_i2, ReadScanEnableResponse { _status, _scan_enable }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteScanEnable {
    _scan_enable: u8,
}

impl WriteScanEnable {
    pub fn get_scan_enable(&self) -> u8 {
        self._scan_enable
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteScanEnable> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1A {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _scan_enable) = try_parse!(_i0, le_u8);
        Ok((_i1, WriteScanEnable { _scan_enable }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteScanEnableResponse {
    _status: ResponseStatus,
}

impl WriteScanEnableResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteScanEnableResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1A {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteScanEnableResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadPageScanActivity {
}

impl ReadPageScanActivity {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadPageScanActivity> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1B {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadPageScanActivity {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadPageScanActivityResponse {
    _status: ResponseStatus,
    _page_scan_interval: u16,
    _page_scan_window: u16,
}

impl ReadPageScanActivityResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_page_scan_interval(&self) -> u16 {
        self._page_scan_interval
    }

    pub fn get_page_scan_window(&self) -> u16 {
        self._page_scan_window
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadPageScanActivityResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1B {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _page_scan_interval) = try_parse!(_i1, le_u16);
        let (_i3, _page_scan_window) = try_parse!(_i2, le_u16);
        Ok((_i3, ReadPageScanActivityResponse { _status, _page_scan_interval, _page_scan_window }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WritePageScanActivity {
    _page_scan_interval: u16,
    _page_scan_window: u16,
}

impl WritePageScanActivity {
    pub fn get_page_scan_interval(&self) -> u16 {
        self._page_scan_interval
    }

    pub fn get_page_scan_window(&self) -> u16 {
        self._page_scan_window
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WritePageScanActivity> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1C {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _page_scan_interval) = try_parse!(_i0, le_u16);
        let (_i2, _page_scan_window) = try_parse!(_i1, le_u16);
        Ok((_i2, WritePageScanActivity { _page_scan_interval, _page_scan_window }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WritePageScanActivityResponse {
    _status: ResponseStatus,
}

impl WritePageScanActivityResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WritePageScanActivityResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1C {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WritePageScanActivityResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadInquiryScanActivity {
}

impl ReadInquiryScanActivity {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadInquiryScanActivity> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1D {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadInquiryScanActivity {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadInquiryScanActivityResponse {
    _status: ResponseStatus,
    _inquiry_scan_interval: u16,
    _inquiry_scan_window: u16,
}

impl ReadInquiryScanActivityResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_inquiry_scan_interval(&self) -> u16 {
        self._inquiry_scan_interval
    }

    pub fn get_inquiry_scan_window(&self) -> u16 {
        self._inquiry_scan_window
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadInquiryScanActivityResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1D {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _inquiry_scan_interval) = try_parse!(_i1, le_u16);
        let (_i3, _inquiry_scan_window) = try_parse!(_i2, le_u16);
        Ok((_i3, ReadInquiryScanActivityResponse { _status, _inquiry_scan_interval, _inquiry_scan_window }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteInquiryScanActivity {
    _inquiry_scan_interval: u16,
    _inquiry_scan_window: u16,
}

impl WriteInquiryScanActivity {
    pub fn get_inquiry_scan_interval(&self) -> u16 {
        self._inquiry_scan_interval
    }

    pub fn get_inquiry_scan_window(&self) -> u16 {
        self._inquiry_scan_window
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteInquiryScanActivity> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1E {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _inquiry_scan_interval) = try_parse!(_i0, le_u16);
        let (_i2, _inquiry_scan_window) = try_parse!(_i1, le_u16);
        Ok((_i2, WriteInquiryScanActivity { _inquiry_scan_interval, _inquiry_scan_window }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteInquiryScanActivityResponse {
    _status: ResponseStatus,
}

impl WriteInquiryScanActivityResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteInquiryScanActivityResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1E {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteInquiryScanActivityResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadExtendedInquiryResponse {
}

impl ReadExtendedInquiryResponse {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadExtendedInquiryResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x51 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadExtendedInquiryResponse {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadExtendedInquiryResponseResponse {
    _status: ResponseStatus,
    _fec_required: u8,
    _response_buffer: Vec<u8>,
    _advertising_data: Vec<BasicDataType>,
}

impl ReadExtendedInquiryResponseResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_fec_required(&self) -> u8 {
        self._fec_required
    }

    pub fn get_advertising_data(&self) -> &[BasicDataType] {
        &self._advertising_data
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadExtendedInquiryResponseResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x51 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _fec_required) = try_parse!(_i1, le_u8);
        let (_i3, _response_buffer) = try_parse!(_i2, count!(le_u8, 240));
        let (_, _advertising_data) = try_parse!(&_i2[..240 as usize], many0!(complete!(BasicDataType::parse)));
        Ok((_i3, ReadExtendedInquiryResponseResponse { _status, _fec_required, _response_buffer, _advertising_data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteExtendedInquiryResponse {
    _fec_required: u8,
    _response_buffer: Vec<u8>,
    _advertising_data: Vec<BasicDataType>,
}

impl WriteExtendedInquiryResponse {
    pub fn get_fec_required(&self) -> u8 {
        self._fec_required
    }

    pub fn get_advertising_data(&self) -> &[BasicDataType] {
        &self._advertising_data
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteExtendedInquiryResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x52 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _fec_required) = try_parse!(_i0, le_u8);
        let (_i2, _response_buffer) = try_parse!(_i1, count!(le_u8, 240));
        let (_, _advertising_data) = try_parse!(&_i1[..240 as usize], many0!(complete!(BasicDataType::parse)));
        Ok((_i2, WriteExtendedInquiryResponse { _fec_required, _response_buffer, _advertising_data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteExtendedInquiryResponseResponse {
    _status: ResponseStatus,
}

impl WriteExtendedInquiryResponseResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteExtendedInquiryResponseResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x52 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteExtendedInquiryResponseResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadLeHostSupport {
}

impl ReadLeHostSupport {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadLeHostSupport> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6C {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, ReadLeHostSupport {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ReadLeHostSupportResponse {
    _status: ResponseStatus,
    _le_supported_host: u8,
    _simultaneous_le_host: u8,
}

impl ReadLeHostSupportResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_le_supported_host(&self) -> u8 {
        self._le_supported_host
    }

    pub fn get_simultaneous_le_host(&self) -> u8 {
        self._simultaneous_le_host
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], ReadLeHostSupportResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6C {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _le_supported_host) = try_parse!(_i1, le_u8);
        let (_i3, _simultaneous_le_host) = try_parse!(_i2, le_u8);
        Ok((_i3, ReadLeHostSupportResponse { _status, _le_supported_host, _simultaneous_le_host }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteLeHostSupport {
    _le_supported_host: u8,
    _simultaneous_le_host: u8,
}

impl WriteLeHostSupport {
    pub fn get_le_supported_host(&self) -> u8 {
        self._le_supported_host
    }

    pub fn get_simultaneous_le_host(&self) -> u8 {
        self._simultaneous_le_host
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteLeHostSupport> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6D {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _le_supported_host) = try_parse!(_i0, le_u8);
        let (_i2, _simultaneous_le_host) = try_parse!(_i1, le_u8);
        Ok((_i2, WriteLeHostSupport { _le_supported_host, _simultaneous_le_host }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct WriteLeHostSupportResponse {
    _status: ResponseStatus,
}

impl WriteLeHostSupportResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], WriteLeHostSupportResponse> {
        if _ogf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6D {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, WriteLeHostSupportResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetEventMask {
    _le_event_mask: Vec<u8>,
}

impl LeSetEventMask {
    pub fn get_le_event_mask(&self) -> &[u8] {
        &self._le_event_mask
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetEventMask> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _le_event_mask) = try_parse!(_i0, count!(le_u8, 8));
        Ok((_i1, LeSetEventMask { _le_event_mask }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetEventMaskResponse {
    _status: ResponseStatus,
}

impl LeSetEventMaskResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetEventMaskResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetEventMaskResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeReadBufferSize {
}

impl LeReadBufferSize {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeReadBufferSize> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, LeReadBufferSize {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeReadBufferSizeResponse {
    _status: ResponseStatus,
    _hc_le_data_packet_length: u16,
    _hc_total_num_le_data_packets: u8,
}

impl LeReadBufferSizeResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_hc_le_data_packet_length(&self) -> u16 {
        self._hc_le_data_packet_length
    }

    pub fn get_hc_total_num_le_data_packets(&self) -> u8 {
        self._hc_total_num_le_data_packets
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeReadBufferSizeResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _hc_le_data_packet_length) = try_parse!(_i1, le_u16);
        let (_i3, _hc_total_num_le_data_packets) = try_parse!(_i2, le_u8);
        Ok((_i3, LeReadBufferSizeResponse { _status, _hc_le_data_packet_length, _hc_total_num_le_data_packets }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeReadLocalSupportedFeatures {
}

impl LeReadLocalSupportedFeatures {
    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeReadLocalSupportedFeatures> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        Ok((_i0, LeReadLocalSupportedFeatures {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeReadLocalSupportedFeaturesResponse {
    _status: ResponseStatus,
    _le_features: Vec<u8>,
}

impl LeReadLocalSupportedFeaturesResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_le_features(&self) -> &[u8] {
        &self._le_features
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeReadLocalSupportedFeaturesResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _le_features) = try_parse!(_i1, count!(le_u8, 8));
        Ok((_i2, LeReadLocalSupportedFeaturesResponse { _status, _le_features }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetRandomAddressCommand {
    _random_address: Vec<u8>,
}

impl LeSetRandomAddressCommand {
    pub fn get_random_address(&self) -> &[u8] {
        &self._random_address
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetRandomAddressCommand> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _random_address) = try_parse!(_i0, count!(le_u8, 6));
        Ok((_i1, LeSetRandomAddressCommand { _random_address }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetRandomAddressCommandResponse {
    _status: ResponseStatus,
}

impl LeSetRandomAddressCommandResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetRandomAddressCommandResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetRandomAddressCommandResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetAdvertisingParameters {
    _advertising_interval_min: u16,
    _advertising_interval_max: u16,
    _advertising_type: u8,
    _own_address_type: u8,
    _peer_address_type: u8,
    _peer_address: Vec<u8>,
    _advertising_channel_map: u8,
    _advertising_filter_policy: u8,
}

impl LeSetAdvertisingParameters {
    pub fn get_advertising_interval_min(&self) -> u16 {
        self._advertising_interval_min
    }

    pub fn get_advertising_interval_max(&self) -> u16 {
        self._advertising_interval_max
    }

    pub fn get_advertising_type(&self) -> u8 {
        self._advertising_type
    }

    pub fn get_own_address_type(&self) -> u8 {
        self._own_address_type
    }

    pub fn get_peer_address_type(&self) -> u8 {
        self._peer_address_type
    }

    pub fn get_peer_address(&self) -> &[u8] {
        &self._peer_address
    }

    pub fn get_advertising_channel_map(&self) -> u8 {
        self._advertising_channel_map
    }

    pub fn get_advertising_filter_policy(&self) -> u8 {
        self._advertising_filter_policy
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetAdvertisingParameters> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _advertising_interval_min) = try_parse!(_i0, le_u16);
        let (_i2, _advertising_interval_max) = try_parse!(_i1, le_u16);
        let (_i3, _advertising_type) = try_parse!(_i2, le_u8);
        let (_i4, _own_address_type) = try_parse!(_i3, le_u8);
        let (_i5, _peer_address_type) = try_parse!(_i4, le_u8);
        let (_i6, _peer_address) = try_parse!(_i5, count!(le_u8, 6));
        let (_i7, _advertising_channel_map) = try_parse!(_i6, le_u8);
        let (_i8, _advertising_filter_policy) = try_parse!(_i7, le_u8);
        Ok((_i8, LeSetAdvertisingParameters { _advertising_interval_min, _advertising_interval_max, _advertising_type, _own_address_type, _peer_address_type, _peer_address, _advertising_channel_map, _advertising_filter_policy }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetAdvertisingParametersResponse {
    _status: ResponseStatus,
}

impl LeSetAdvertisingParametersResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetAdvertisingParametersResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x6 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetAdvertisingParametersResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetAdvertisingData {
    _advertising_data_length: u8,
    _advertising_data_buffer: Vec<u8>,
    _advertising_data: Vec<BasicDataType>,
}

impl LeSetAdvertisingData {
    pub fn get_advertising_data(&self) -> &[BasicDataType] {
        &self._advertising_data
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetAdvertisingData> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _advertising_data_length) = try_parse!(_i0, le_u8);
        let (_i2, _advertising_data_buffer) = try_parse!(_i1, count!(le_u8, _advertising_data_length as usize));
        let (_, _advertising_data) = try_parse!(&_i1[.._advertising_data_length as usize], many0!(complete!(BasicDataType::parse)));
        Ok((_i2, LeSetAdvertisingData { _advertising_data_length, _advertising_data_buffer, _advertising_data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetAdvertisingDataResponse {
    _status: ResponseStatus,
}

impl LeSetAdvertisingDataResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetAdvertisingDataResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetAdvertisingDataResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetScanParameters {
    _le_scan_type: u8,
    _le_scan_interval: u16,
    _le_scan_window: u16,
    _own_address_type: u8,
    _scanning_filter_policy: u8,
}

impl LeSetScanParameters {
    pub fn get_le_scan_type(&self) -> u8 {
        self._le_scan_type
    }

    pub fn get_le_scan_interval(&self) -> u16 {
        self._le_scan_interval
    }

    pub fn get_le_scan_window(&self) -> u16 {
        self._le_scan_window
    }

    pub fn get_own_address_type(&self) -> u8 {
        self._own_address_type
    }

    pub fn get_scanning_filter_policy(&self) -> u8 {
        self._scanning_filter_policy
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetScanParameters> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0xB {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _le_scan_type) = try_parse!(_i0, le_u8);
        let (_i2, _le_scan_interval) = try_parse!(_i1, le_u16);
        let (_i3, _le_scan_window) = try_parse!(_i2, le_u16);
        let (_i4, _own_address_type) = try_parse!(_i3, le_u8);
        let (_i5, _scanning_filter_policy) = try_parse!(_i4, le_u8);
        Ok((_i5, LeSetScanParameters { _le_scan_type, _le_scan_interval, _le_scan_window, _own_address_type, _scanning_filter_policy }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetScanParametersResponse {
    _status: ResponseStatus,
}

impl LeSetScanParametersResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetScanParametersResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0xB {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetScanParametersResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetScanEnable {
    _le_scan_enable: u8,
    _filter_duplicates: u8,
}

impl LeSetScanEnable {
    pub fn get_le_scan_enable(&self) -> u8 {
        self._le_scan_enable
    }

    pub fn get_filter_duplicates(&self) -> u8 {
        self._filter_duplicates
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetScanEnable> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0xC {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _le_scan_enable) = try_parse!(_i0, le_u8);
        let (_i2, _filter_duplicates) = try_parse!(_i1, le_u8);
        Ok((_i2, LeSetScanEnable { _le_scan_enable, _filter_duplicates }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeSetScanEnableResponse {
    _status: ResponseStatus,
}

impl LeSetScanEnableResponse {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn parse(_i0: &[u8], _ogf: u8, _ocf: u16) -> IResult<&[u8], LeSetScanEnableResponse> {
        if _ogf != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _ocf != 0xC {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        Ok((_i1, LeSetScanEnableResponse { _status }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct EndThing {
}

impl EndThing {
    pub fn parse(_i0: &[u8]) -> IResult<&[u8], EndThing> {
        Ok((_i0, EndThing {  }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct IncompleteServiceUuid16 {
    _len: u8,
    _uuids: Vec<u16>,
}

impl IncompleteServiceUuid16 {
    pub fn get_uuids(&self) -> &[u16] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], IncompleteServiceUuid16> {
        if _type != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u16, (_len / 0x2) as usize));
        Ok((_i1, IncompleteServiceUuid16 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct CompleteServiceUuid16 {
    _len: u8,
    _uuids: Vec<u16>,
}

impl CompleteServiceUuid16 {
    pub fn get_uuids(&self) -> &[u16] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], CompleteServiceUuid16> {
        if _type != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u16, (_len / 0x2) as usize));
        Ok((_i1, CompleteServiceUuid16 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct IncompleteServiceUuid32 {
    _len: u8,
    _uuids: Vec<u32>,
}

impl IncompleteServiceUuid32 {
    pub fn get_uuids(&self) -> &[u32] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], IncompleteServiceUuid32> {
        if _type != 0x4 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u32, (_len / 0x4) as usize));
        Ok((_i1, IncompleteServiceUuid32 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct CompleteServiceUuid32 {
    _len: u8,
    _uuids: Vec<u32>,
}

impl CompleteServiceUuid32 {
    pub fn get_uuids(&self) -> &[u32] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], CompleteServiceUuid32> {
        if _type != 0x5 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u32, (_len / 0x4) as usize));
        Ok((_i1, CompleteServiceUuid32 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct IncompleteServiceUuid128 {
    _len: u8,
    _uuids: Vec<Vec<u8>>,
}

impl IncompleteServiceUuid128 {
    pub fn get_uuids(&self) -> &[Vec<u8>] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], IncompleteServiceUuid128> {
        if _type != 0x6 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(count!(le_u8, 16), (_len / 0x10) as usize));
        Ok((_i1, IncompleteServiceUuid128 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct CompleteServiceUuid128 {
    _len: u8,
    _uuids: Vec<Vec<u8>>,
}

impl CompleteServiceUuid128 {
    pub fn get_uuids(&self) -> &[Vec<u8>] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], CompleteServiceUuid128> {
        if _type != 0x7 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(count!(le_u8, 16), (_len / 0x10) as usize));
        Ok((_i1, CompleteServiceUuid128 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ShortenedLocalName {
    _len: u8,
    _local_name: String,
}

impl ShortenedLocalName {
    pub fn get_local_name(&self) -> &String {
        &self._local_name
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ShortenedLocalName> {
        if _type != 0x8 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _local_name) = try_parse!(_i0, map_res!(take!(_len), |v: &[u8]| String::from_utf8(v.to_owned())));
        Ok((_i1, ShortenedLocalName { _len, _local_name }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct CompleteLocalName {
    _len: u8,
    _local_name: String,
}

impl CompleteLocalName {
    pub fn get_local_name(&self) -> &String {
        &self._local_name
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], CompleteLocalName> {
        if _type != 0x9 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _local_name) = try_parse!(_i0, map_res!(take!(_len), |v: &[u8]| String::from_utf8(v.to_owned())));
        Ok((_i1, CompleteLocalName { _len, _local_name }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct AdFlags {
    _len: u8,
    _flags: Vec<u8>,
}

impl AdFlags {
    pub fn get_flags(&self) -> &[u8] {
        &self._flags
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], AdFlags> {
        if _type != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _flags) = try_parse!(_i0, count!(le_u8, _len as usize));
        Ok((_i1, AdFlags { _len, _flags }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ManufacturerSpecificData {
    _len: u8,
    _company_identifier_code: u16,
    _data: Vec<u8>,
}

impl ManufacturerSpecificData {
    pub fn get_company_identifier_code(&self) -> u16 {
        self._company_identifier_code
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ManufacturerSpecificData> {
        if _type != 0xFF {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _company_identifier_code) = try_parse!(_i0, le_u16);
        let (_i2, _data) = try_parse!(_i1, count!(le_u8, (_len - 0x2) as usize));
        Ok((_i2, ManufacturerSpecificData { _len, _company_identifier_code, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct TxPowerLevel {
    _level: i8,
}

impl TxPowerLevel {
    pub fn get_level(&self) -> i8 {
        self._level
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], TxPowerLevel> {
        if _type != 0xA {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _len != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _level) = try_parse!(_i0, le_i8);
        Ok((_i1, TxPowerLevel { _level }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct SlaveConnectionIntervalRange {
    _min: u16,
    _max: u16,
}

impl SlaveConnectionIntervalRange {
    pub fn get_min(&self) -> u16 {
        self._min
    }

    pub fn get_max(&self) -> u16 {
        self._max
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], SlaveConnectionIntervalRange> {
        if _type != 0x12 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _len != 0x4 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _min) = try_parse!(_i0, le_u16);
        let (_i2, _max) = try_parse!(_i1, le_u16);
        Ok((_i2, SlaveConnectionIntervalRange { _min, _max }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceSolicitation16 {
    _len: u8,
    _uuids: Vec<u16>,
}

impl ServiceSolicitation16 {
    pub fn get_uuids(&self) -> &[u16] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceSolicitation16> {
        if _type != 0x14 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u16, (_len / 0x2) as usize));
        Ok((_i1, ServiceSolicitation16 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceSolicitation32 {
    _len: u8,
    _uuids: Vec<u32>,
}

impl ServiceSolicitation32 {
    pub fn get_uuids(&self) -> &[u32] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceSolicitation32> {
        if _type != 0x1F {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(le_u32, (_len / 0x4) as usize));
        Ok((_i1, ServiceSolicitation32 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceSolicitation128 {
    _len: u8,
    _uuids: Vec<Vec<u8>>,
}

impl ServiceSolicitation128 {
    pub fn get_uuids(&self) -> &[Vec<u8>] {
        &self._uuids
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceSolicitation128> {
        if _type != 0x15 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuids) = try_parse!(_i0, count!(count!(le_u8, 16), (_len / 0x10) as usize));
        Ok((_i1, ServiceSolicitation128 { _len, _uuids }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceData16 {
    _len: u8,
    _uuid: u16,
    _data: Vec<u8>,
}

impl ServiceData16 {
    pub fn get_uuid(&self) -> u16 {
        self._uuid
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceData16> {
        if _type != 0x16 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuid) = try_parse!(_i0, le_u16);
        let (_i2, _data) = try_parse!(_i1, count!(le_u8, (_len - 0x2) as usize));
        Ok((_i2, ServiceData16 { _len, _uuid, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceData32 {
    _len: u8,
    _uuid: u32,
    _data: Vec<u8>,
}

impl ServiceData32 {
    pub fn get_uuid(&self) -> u32 {
        self._uuid
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceData32> {
        if _type != 0x20 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuid) = try_parse!(_i0, le_u32);
        let (_i2, _data) = try_parse!(_i1, count!(le_u8, (_len - 0x4) as usize));
        Ok((_i2, ServiceData32 { _len, _uuid, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ServiceData128 {
    _len: u8,
    _uuid: Vec<u8>,
    _data: Vec<u8>,
}

impl ServiceData128 {
    pub fn get_uuid(&self) -> &[u8] {
        &self._uuid
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], ServiceData128> {
        if _type != 0x21 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _uuid) = try_parse!(_i0, count!(le_u8, 16));
        let (_i2, _data) = try_parse!(_i1, count!(le_u8, (_len - 0x10) as usize));
        Ok((_i2, ServiceData128 { _len, _uuid, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Appearance {
    _appearance: u16,
}

impl Appearance {
    pub fn get_appearance(&self) -> u16 {
        self._appearance
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], Appearance> {
        if _type != 0x19 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        if _len != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _appearance) = try_parse!(_i0, le_u16);
        Ok((_i1, Appearance { _appearance }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct BasicDataType {
    _length: u8,
    _type: u8,
    _data: BasicDataType_Data,
}

impl BasicDataType {
    pub fn get_data(&self) -> &BasicDataType_Data {
        &self._data
    }

    pub fn parse(_i0: &[u8]) -> IResult<&[u8], BasicDataType> {
        let (_i1, _length) = try_parse!(_i0, le_u8);
        let (_i2, _type) = try_parse!(_i1, le_u8);
        let (_i3, _data) = try_parse!(_i2, alt!(
            call!(IncompleteServiceUuid16::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::IncompleteServiceUuid16(v)} |
            call!(CompleteServiceUuid16::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::CompleteServiceUuid16(v)} |
            call!(IncompleteServiceUuid32::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::IncompleteServiceUuid32(v)} |
            call!(CompleteServiceUuid32::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::CompleteServiceUuid32(v)} |
            call!(IncompleteServiceUuid128::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::IncompleteServiceUuid128(v)} |
            call!(CompleteServiceUuid128::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::CompleteServiceUuid128(v)} |
            call!(ShortenedLocalName::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ShortenedLocalName(v)} |
            call!(CompleteLocalName::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::CompleteLocalName(v)} |
            call!(AdFlags::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ADFlags(v)} |
            call!(ManufacturerSpecificData::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ManufacturerSpecificData(v)} |
            call!(TxPowerLevel::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::TxPowerLevel(v)} |
            call!(SlaveConnectionIntervalRange::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::SlaveConnectionIntervalRange(v)} |
            call!(ServiceSolicitation16::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceSolicitation16(v)} |
            call!(ServiceSolicitation32::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceSolicitation32(v)} |
            call!(ServiceSolicitation128::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceSolicitation128(v)} |
            call!(ServiceData16::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceData16(v)} |
            call!(ServiceSolicitation32::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceData32(v)} |
            call!(ServiceData128::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::ServiceData128(v)} |
            call!(Appearance::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::Appearance(v)} |
            call!(UnsupportedDataType::parse, _type, _length - 0x1) => {|v| BasicDataType_Data::UnsupportedDataType(v)}
    ));
        Ok((_i3, BasicDataType { _length, _type, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct UnsupportedDataType {
    _type: u8,
    _len: u8,
    _data: Vec<u8>,
}

impl UnsupportedDataType {
    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8, _len: u8) -> IResult<&[u8], UnsupportedDataType> {
        let (_i1, _data) = try_parse!(_i0, count!(le_u8, _len as usize));
        Ok((_i1, UnsupportedDataType { _type, _len, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeMetaEvent {
    _subevent_code: u8,
    _event: LeMetaEvent_Event,
}

impl LeMetaEvent {
    pub fn get_event(&self) -> &LeMetaEvent_Event {
        &self._event
    }

    pub fn parse(_i0: &[u8], _event_code: u8) -> IResult<&[u8], LeMetaEvent> {
        if _event_code != 0x3E {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _subevent_code) = try_parse!(_i0, le_u8);
        let (_i2, _event) = try_parse!(_i1, alt!(
            call!(LeConnectionComplete::parse, _subevent_code) => {|v| LeMetaEvent_Event::LeConnectionComplete(v)} |
            call!(LeAdvertisingReport::parse, _subevent_code) => {|v| LeMetaEvent_Event::LeAdvertisingReport(v)} |
            call!(LeConnectionUpdateComplete::parse, _subevent_code) => {|v| LeMetaEvent_Event::LeConnectionUpdateComplete(v)} |
            call!(LeReadRemoteFeaturesComplete::parse, _subevent_code) => {|v| LeMetaEvent_Event::LeReadRemoteFeaturesComplete(v)}
    ));
        Ok((_i2, LeMetaEvent { _subevent_code, _event }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeConnectionComplete {
    _status: ResponseStatus,
    _handle_and_flags: u16,
    _role: u8,
    _peer_address_type: u8,
    _peer_address: Vec<u8>,
    _conn_interval: u16,
    _conn_latency: u16,
    _supervision_timeout: u16,
    _master_clock_accuracy: u8,
}

impl LeConnectionComplete {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_handle(&self) -> u16 {
        (self._handle_and_flags & 0xFFF) as u16
    }

    pub fn get_role(&self) -> u8 {
        self._role
    }

    pub fn get_peer_address_type(&self) -> u8 {
        self._peer_address_type
    }

    pub fn get_peer_address(&self) -> &[u8] {
        &self._peer_address
    }

    pub fn get_conn_interval(&self) -> u16 {
        self._conn_interval
    }

    pub fn get_conn_latency(&self) -> u16 {
        self._conn_latency
    }

    pub fn get_supervision_timeout(&self) -> u16 {
        self._supervision_timeout
    }

    pub fn get_master_clock_accuracy(&self) -> u8 {
        self._master_clock_accuracy
    }

    pub fn parse(_i0: &[u8], _subevent_code: u8) -> IResult<&[u8], LeConnectionComplete> {
        if _subevent_code != 0x1 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _handle_and_flags) = try_parse!(_i1, le_u16);
        let _connection_handle: u16 = (_handle_and_flags & 0xFFF) as u16;
        let (_i3, _role) = try_parse!(_i2, le_u8);
        let (_i4, _peer_address_type) = try_parse!(_i3, le_u8);
        let (_i5, _peer_address) = try_parse!(_i4, count!(le_u8, 6));
        let (_i6, _conn_interval) = try_parse!(_i5, le_u16);
        let (_i7, _conn_latency) = try_parse!(_i6, le_u16);
        let (_i8, _supervision_timeout) = try_parse!(_i7, le_u16);
        let (_i9, _master_clock_accuracy) = try_parse!(_i8, le_u8);
        Ok((_i9, LeConnectionComplete { _status, _handle_and_flags, _role, _peer_address_type, _peer_address, _conn_interval, _conn_latency, _supervision_timeout, _master_clock_accuracy }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeAdvertisingReport {
    _num_reports: u8,
    _event_type: u8,
    _address_type: u8,
    _address: Vec<u8>,
    _data_len: u8,
    _data_buffer: Vec<u8>,
    _data: Vec<BasicDataType>,
    _rssi: u8,
}

impl LeAdvertisingReport {
    pub fn get_event_type(&self) -> u8 {
        self._event_type
    }

    pub fn get_address_type(&self) -> u8 {
        self._address_type
    }

    pub fn get_address(&self) -> &[u8] {
        &self._address
    }

    pub fn get_data(&self) -> &[BasicDataType] {
        &self._data
    }

    pub fn get_rssi(&self) -> u8 {
        self._rssi
    }

    pub fn parse(_i0: &[u8], _subevent_code: u8) -> IResult<&[u8], LeAdvertisingReport> {
        if _subevent_code != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _num_reports) = try_parse!(_i0, le_u8);
        let (_i2, _event_type) = try_parse!(_i1, le_u8);
        let (_i3, _address_type) = try_parse!(_i2, le_u8);
        let (_i4, _address) = try_parse!(_i3, count!(le_u8, 6));
        let (_i5, _data_len) = try_parse!(_i4, le_u8);
        let (_i6, _data_buffer) = try_parse!(_i5, count!(le_u8, _data_len as usize));
        let (_, _data) = try_parse!(&_i5[.._data_len as usize], many0!(complete!(BasicDataType::parse)));
        let (_i7, _rssi) = try_parse!(_i6, le_u8);
        Ok((_i7, LeAdvertisingReport { _num_reports, _event_type, _address_type, _address, _data_len, _data_buffer, _data, _rssi }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeConnectionUpdateComplete {
    _status: ResponseStatus,
    _connection_handle: u16,
    _conn_interval: u16,
    _conn_latency: u16,
    _supervision_timeout: u16,
}

impl LeConnectionUpdateComplete {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_handle(&self) -> u16 {
        self._connection_handle
    }

    pub fn get_conn_interval(&self) -> u16 {
        self._conn_interval
    }

    pub fn get_conn_latency(&self) -> u16 {
        self._conn_latency
    }

    pub fn get_supervision_timeout(&self) -> u16 {
        self._supervision_timeout
    }

    pub fn parse(_i0: &[u8], _subevent_code: u8) -> IResult<&[u8], LeConnectionUpdateComplete> {
        if _subevent_code != 0x3 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _connection_handle) = try_parse!(_i1, le_u16);
        let (_i3, _conn_interval) = try_parse!(_i2, le_u16);
        let (_i4, _conn_latency) = try_parse!(_i3, le_u16);
        let (_i5, _supervision_timeout) = try_parse!(_i4, le_u16);
        Ok((_i5, LeConnectionUpdateComplete { _status, _connection_handle, _conn_interval, _conn_latency, _supervision_timeout }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LeReadRemoteFeaturesComplete {
    _status: ResponseStatus,
    _connection_handle: u16,
    _le_features: Vec<u8>,
}

impl LeReadRemoteFeaturesComplete {
    pub fn get_status(&self) -> &ResponseStatus {
        &self._status
    }

    pub fn get_connection_handle(&self) -> u16 {
        self._connection_handle
    }

    pub fn get_le_features(&self) -> &[u8] {
        &self._le_features
    }

    pub fn parse(_i0: &[u8], _subevent_code: u8) -> IResult<&[u8], LeReadRemoteFeaturesComplete> {
        if _subevent_code != 0x4 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _status) = try_parse!(_i0, ResponseStatus::parse);
        let (_i2, _connection_handle) = try_parse!(_i1, le_u16);
        let (_i3, _le_features) = try_parse!(_i2, count!(le_u8, 8));
        Ok((_i3, LeReadRemoteFeaturesComplete { _status, _connection_handle, _le_features }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct HciAclData {
    _handle_and_flags: u16,
    _data_total_length: u16,
    _data: Vec<u8>,
}

impl HciAclData {
    pub fn get_handle(&self) -> u16 {
        (self._handle_and_flags & 0xFFF) as u16
    }

    pub fn get_flags(&self) -> u8 {
        (self._handle_and_flags >> 0xC) as u8
    }

    pub fn get_data(&self) -> &[u8] {
        &self._data
    }

    pub fn parse(_i0: &[u8], _type: u8) -> IResult<&[u8], HciAclData> {
        if _type != 0x2 {
            return Err(nom::Err::Error(nom::Context::Code(_i0, nom::ErrorKind::Tag)));
        }
        let (_i1, _handle_and_flags) = try_parse!(_i0, le_u16);
        let _handle: u16 = (_handle_and_flags & 0xFFF) as u16;
        let _flags: u8 = (_handle_and_flags >> 0xC) as u8;
        let (_i2, _data_total_length) = try_parse!(_i1, le_u16);
        let (_i3, _data) = try_parse!(_i2, count!(le_u8, _data_total_length as usize));
        Ok((_i3, HciAclData { _handle_and_flags, _data_total_length, _data }))
    }

}


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct HciMessage {
    _message_type: u8,
    _message: HciMessage_Message,
}

impl HciMessage {
    pub fn get_message(&self) -> &HciMessage_Message {
        &self._message
    }

    pub fn parse(_i0: &[u8]) -> IResult<&[u8], HciMessage> {
        let (_i1, _message_type) = try_parse!(_i0, le_u8);
        let (_i2, _message) = try_parse!(_i1, alt!(
            call!(HciCommand::parse, _message_type) => {|v| HciMessage_Message::HciCommand(v)} |
            call!(HciAclData::parse, _message_type) => {|v| HciMessage_Message::HciAclData(v)} |
            call!(HciEvent::parse, _message_type) => {|v| HciMessage_Message::HciEvent(v)}
    ));
        Ok((_i2, HciMessage { _message_type, _message }))
    }

}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum HciEvent_Event {
    DisconnectionComplete(DisconnectionComplete),
    CommandComplete(CommandComplete),
    LeMetaEvent(LeMetaEvent),
    UnknownEvent(UnknownEvent),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum CommandComplete_Response {
    NoAssociatedCommand(NoAssociatedCommand),
    Reset(ResetResponse),
    SetEventFilter(SetEventFilterResponse),
    Flush(FlushResponse),
    WriteLocalName(WriteLocalNameResponse),
    ReadLocalName(ReadLocalNameResponse),
    ReadConnectionAcceptTimeout(ReadConnectionAcceptTimeoutResponse),
    WriteConnectionAcceptTimeout(WriteConnectionAcceptTimeoutResponse),
    ReadPageTimeout(ReadPageTimeoutResponse),
    WritePageTimeout(WritePageTimeoutResponse),
    ReadScanEnable(ReadScanEnableResponse),
    WriteScanEnable(WriteScanEnableResponse),
    ReadPageScanActivity(ReadPageScanActivityResponse),
    WritePageScanActivity(WritePageScanActivityResponse),
    ReadInquiryScanActivity(ReadInquiryScanActivityResponse),
    WriteInquiryScanActivity(WriteInquiryScanActivityResponse),
    ReadExtendedInquiryResponse(ReadExtendedInquiryResponseResponse),
    WriteExtendedInquiryResponse(WriteExtendedInquiryResponseResponse),
    ReadLeHostSupport(ReadLeHostSupportResponse),
    WriteLeHostSupport(WriteLeHostSupportResponse),
    LeSetEventMask(LeSetEventMask),
    LeSetEventMaskResponse(LeSetEventMaskResponse),
    LeReadBufferSize(LeReadBufferSizeResponse),
    LeReadLocalSupportedFeatures(LeReadLocalSupportedFeaturesResponse),
    LeSetRandomAddressCommand(LeSetRandomAddressCommandResponse),
    LeSetAdvertisingParameters(LeSetAdvertisingParametersResponse),
    LESetAdvertisingData(LeSetAdvertisingDataResponse),
    LeSetScanParameters(LeSetScanParametersResponse),
    LeSetScanEnable(LeSetScanEnableResponse),
    UnknownCommand(UnknownCommand),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum HciCommand_Command {
    Reset(Reset),
    SetEventFilter(SetEventFilter),
    Flush(Flush),
    WriteLocalName(WriteLocalName),
    ReadLocalName(ReadLocalName),
    ReadConnectionAcceptTimeout(ReadConnectionAcceptTimeout),
    WriteConnectionAcceptTimeout(WriteConnectionAcceptTimeout),
    ReadPageTimeout(ReadPageTimeout),
    WritePageTimeout(WritePageTimeout),
    ReadScanEnable(ReadScanEnable),
    WriteScanEnable(WriteScanEnable),
    ReadPageScanActivity(ReadPageScanActivity),
    WritePageScanActivity(WritePageScanActivity),
    ReadInquiryScanActivity(ReadInquiryScanActivity),
    WriteInquiryScanActivity(WriteInquiryScanActivity),
    LESetAdvertisingData(LeSetAdvertisingData),
    Unknown(Unknown),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum SetEventFilter_Filter {
    ClearAllFilter(ClearAllFilter),
    InquiryResult(InquiryResult),
    ConnectionSetup(ConnectionSetup),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum FilterCondition_Value {
    AllDevices(AllDevices),
    MatchClass(MatchClass),
    MatchAddress(MatchAddress),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum BasicDataType_Data {
    IncompleteServiceUuid16(IncompleteServiceUuid16),
    CompleteServiceUuid16(CompleteServiceUuid16),
    IncompleteServiceUuid32(IncompleteServiceUuid32),
    CompleteServiceUuid32(CompleteServiceUuid32),
    IncompleteServiceUuid128(IncompleteServiceUuid128),
    CompleteServiceUuid128(CompleteServiceUuid128),
    ShortenedLocalName(ShortenedLocalName),
    CompleteLocalName(CompleteLocalName),
    ADFlags(AdFlags),
    ManufacturerSpecificData(ManufacturerSpecificData),
    TxPowerLevel(TxPowerLevel),
    SlaveConnectionIntervalRange(SlaveConnectionIntervalRange),
    ServiceSolicitation16(ServiceSolicitation16),
    ServiceSolicitation32(ServiceSolicitation32),
    ServiceSolicitation128(ServiceSolicitation128),
    ServiceData16(ServiceData16),
    ServiceData32(ServiceSolicitation32),
    ServiceData128(ServiceData128),
    Appearance(Appearance),
    UnsupportedDataType(UnsupportedDataType),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum LeMetaEvent_Event {
    LeConnectionComplete(LeConnectionComplete),
    LeAdvertisingReport(LeAdvertisingReport),
    LeConnectionUpdateComplete(LeConnectionUpdateComplete),
    LeReadRemoteFeaturesComplete(LeReadRemoteFeaturesComplete),
}


#[allow(non_camel_case_types)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum HciMessage_Message {
    HciCommand(HciCommand),
    HciAclData(HciAclData),
    HciEvent(HciEvent),
}


