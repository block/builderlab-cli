//! Blox orchestrator protocol types and client support.

mod client;

pub use client::{Client, RpcError};

/// Generated Blox orchestrator messages with standard protobuf JSON encoding.
pub mod proto {
    #![allow(deprecated)]
    #![allow(clippy::all)]

    include!(concat!(
        env!("OUT_DIR"),
        "/xyz.block.blox.orchestrator.v1.rs"
    ));
    include!(concat!(
        env!("OUT_DIR"),
        "/xyz.block.blox.orchestrator.v1.serde.rs"
    ));
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use serde_json::json;

    use super::proto::{
        ListWorkstationsRequest, ListWorkstationsResponse, StartWorkstationRequest,
    };

    #[test]
    fn protobuf_json_preserves_presence_and_uses_camel_case() {
        let request = ListWorkstationsRequest {
            include_deleted: Some(false),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"includeDeleted": false})
        );
        assert_eq!(
            serde_json::from_value::<ListWorkstationsRequest>(json!({"include_deleted": false}))
                .unwrap(),
            request
        );
        assert_eq!(
            serde_json::to_value(ListWorkstationsRequest::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn protobuf_json_preserves_large_counts() {
        let response = ListWorkstationsResponse {
            total_count: 9_007_199_254_740_993,
            ..Default::default()
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["totalCount"], "9007199254740993");
        assert_eq!(
            serde_json::from_value::<ListWorkstationsResponse>(value).unwrap(),
            response
        );
    }

    #[test]
    fn generated_messages_round_trip_binary_and_optional_fields() {
        let request = StartWorkstationRequest {
            name: Some("example".to_owned()),
            cpu: Some(0),
            ..Default::default()
        };
        let decoded = StartWorkstationRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(serde_json::to_value(&decoded).unwrap()["cpu"], 0);
    }

    #[test]
    fn newer_servers_can_add_fields_and_statuses() {
        for status in [json!(99), json!("WORKSTATION_STATUS_FUTURE")] {
            let response: ListWorkstationsResponse = serde_json::from_value(json!({
                "newResponseField": true,
                "workstations": [{"name":"future", "status": status, "newWorkstationField": {"nested":1}}]
            })).unwrap();
            assert_eq!(response.workstations[0].status, 0);
            assert_eq!(
                serde_json::to_value(&response).unwrap()["workstations"][0]["name"],
                "future"
            );
        }
    }
}
