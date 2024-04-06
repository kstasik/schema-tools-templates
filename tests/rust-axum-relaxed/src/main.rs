use serde::{Deserialize, Serialize};

use std::{net::SocketAddr, sync::Arc};


#[derive(Clone)]
pub struct Database {}

#[derive(Clone)]
pub struct MessageBus {}

impl Database {
    pub async fn get_smth(&self) -> bool {
        true
    }
}

impl MessageBus {
    pub async fn send(&self) -> bool {
        true
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Coordinates (pub f64, pub f64);

mod api;
mod client;
mod handler {


    use axum::extract::{Json, Path, State};
    use uuid::uuid;
    use validator::Validate;

    use crate::{api, AppState, api::qs::Query};

    pub async fn livez_list(State(state): State<AppState>) -> api::endpoint::LivezListResponse {
        let _result = state.database.get_smth().await;

        api::endpoint::LivezListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn readyz_list(State(state): State<AppState>) -> api::endpoint::ReadyzListResponse {
        let _result = state.database.get_smth().await;

        api::endpoint::ReadyzListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn devices_list_v1(
        Query(query): Query<api::endpoint::DevicesListV1Query>,
        State(state): State<AppState>,
    ) -> Result<api::endpoint::DevicesListV1Response, api::endpoint::DevicesListV1Response> {
        let _result = state.database.get_smth().await;

        if query.for_.map(|f| f.eq("test")).unwrap_or(false) {
            return Ok(api::endpoint::DevicesListV1Response::Status200(api::model::ListDevices200Response {
                pagination: api::model::Pagination::new(
                    1,
                    api::model::PaginationPageSizeVariant::PaginationPageSize10,
                ),
                data: vec![api::model::Device::new(
                    "3801deea-8a6d-46cc-bc60-1e8ead00b0db".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                    uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                    None,
                    None,
                    None,
                    None,
                )],
            }));
        }

        if query
            .filter
            .as_ref()
            .map(|f| {
                f.device_id
                    .as_ref()
                    .map(|f| f.eq("a9604d6a-3f76-476b-bfbf-97a940e879d8"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
        {
            return Ok(api::endpoint::DevicesListV1Response::Status200(api::model::ListDevices200Response {
                pagination: api::model::Pagination::new(
                    1,
                    api::model::PaginationPageSizeVariant::PaginationPageSize10,
                ),
                data: vec![api::model::Device::new(
                    "a9604d6a-3f76-476b-bfbf-97a940e879d8".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                    uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                    None,
                    None,
                    None,
                    None,
                )],
            }));
        } else if query.page.unwrap_or(0) == 2 {
            return Ok(api::endpoint::DevicesListV1Response::Status200(api::model::ListDevices200Response {
                pagination: api::model::Pagination::new(
                    1,
                    api::model::PaginationPageSizeVariant::PaginationPageSize10,
                ),
                data: vec![api::model::Device::new(
                    "138f5d31-4feb-4765-88ad-989dff706b53".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                    uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                    None,
                    None,
                    None,
                    None,
                )],
            }));
        }

        Ok(api::endpoint::DevicesListV1Response::Status200(api::model::ListDevices200Response {
            pagination: api::model::Pagination::new(
                1,
                api::model::PaginationPageSizeVariant::PaginationPageSize10,
            ),
            data: vec![],
        }))
    }

    pub async fn devices_get_v1(
        Path(path): Path<api::endpoint::DeviceGetV1Path>,
        State(state): State<AppState>,
    ) -> api::endpoint::DeviceGetV1Response {
        let _result = state.database.get_smth().await;

        if path.device_id.eq("missing") {
            return api::endpoint::DeviceGetV1Response::Status400(
                api::model::GetDevice400Response {
                    error: api::model::GetDevice400ResponseError {
                        code: api::model::GetDevice400ResponseErrorCodeVariant::NotFound,
                    },
                },
            );
        }

        api::endpoint::DeviceGetV1Response::Status200(api::model::GetDevice200Response {
            data: api::model::Device::new(
                "test".to_string(),
                api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                None,
                None,
                None,
                None,
            ),
        })
    }


    pub async fn location_get_v1(
        State(state): State<AppState>,
    ) -> api::endpoint::LocationGetV1Response {
        let _result = state.database.get_smth().await;

        unreachable!()
    }

    pub async fn locations_create_v1(
        Json(request): Json<api::model::Location>
    ) -> api::endpoint::LocationCreateV1Response {
        api::endpoint::LocationCreateV1Response::Status200(
            api::model::CreateLocation200Response::new(request)
        )
    }


    pub async fn devices_create_v1(
        State(state): State<AppState>,
        Json(request): Json<api::model::Device>,
    ) -> api::endpoint::DeviceCreateV1Response {
        if let Err(_) = request.validate() {
            return api::endpoint::DeviceCreateV1Response::Status400(
                api::model::CreateDevice400Response::new(
                    api::model::CreateDevice400ResponseError::new(
                        api::model::CreateDevice400ResponseErrorCodeVariant::ValidationError
                    ),
                )
            )
        }

        let _result = state.database.get_smth().await;
        let _result2 = state.messagebus.send().await;

        if request.device_id == "conflict" {
            api::endpoint::DeviceCreateV1Response::Status409(
                api::endpoint::DeviceCreateV1Response409Headers {
                    location: "/v1/devices/654".to_string(),
                }
            )
        } else {
            api::endpoint::DeviceCreateV1Response::Status201
        }
    }

    pub async fn accessory_create_v1(
        Json(data): Json<api::model::Accessory>,
    ) -> api::endpoint::AccessoryCreateV1Response {
        match data.accessory_id.as_str() {
            "conflict" => api::endpoint::AccessoryCreateV1Response::Status409(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::ConflictError,
                    },
                },
            ),
            "error" => api::endpoint::AccessoryCreateV1Response::Status400(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::ValidationError,
                    },
                },
            ),
            _ => api::endpoint::AccessoryCreateV1Response::Status400(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::NotFound,
                    },
                },
            ),
        }
    }

    pub async fn accessory_get_v1(
        Path(path): Path<api::endpoint::AccessoryGetV1Path>,
        State(_state): State<AppState>,
    ) -> api::endpoint::AccessoryGetV1Response {
        if path.accessory_id == "invalid" {
            return api::endpoint::AccessoryGetV1Response::Status400(
                api::endpoint::GetAccessory400ResponseWithHeaders {
                    body: api::model::GetAccessory400Response::new(
                        api::model::GetAccessory400ResponseError {
                            code:
                                api::model::GetAccessory400ResponseErrorCodeVariant::ValidationError,
                        },
                    ),
                    headers: api::endpoint::AccessoryGetV1Response400Headers {
                        x_hash_key: "hash-error".to_string(),
                    },
                },
            );
        }

        api::endpoint::AccessoryGetV1Response::Status200(
            api::endpoint::GetAccessory200ResponseWithHeaders {
                body: api::model::GetAccessory200Response::new(api::model::Accessory::new(
                    path.accessory_id,
                )),
                headers: api::endpoint::AccessoryGetV1Response200Headers {
                    x_hash_key: "hash".to_string(),
                },
            },
        )
    }

    pub async fn accessory_get_log_v1(
        State(_state): State<AppState>,
    ) -> api::endpoint::AccessoryLogListV1Response {
        api::endpoint::AccessoryLogListV1Response::Status200("plain-text-data".to_string())
    }
}

#[tokio::main]
async fn main() {
    let database = Arc::new(Database {});
    let messagebus = Arc::new(MessageBus {});

    run_server(database, messagebus, 8080).await
}

#[derive(Clone)]
struct AppState {
    database: Arc<Database>,
    messagebus: Arc<MessageBus>
}

async fn run_server(database: Arc<Database>, messagebus: Arc<MessageBus>, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let devices = api::service::DevicesRouter::new()
        .devices_list_v1(handler::devices_list_v1)
        .device_create_v1(handler::devices_create_v1)
        .device_get_v1(handler::devices_get_v1);

    let accessories = api::service::AccessoriesRouter::new()
        .accessory_create_v1(handler::accessory_create_v1)
        .accessory_log_list_v1(handler::accessory_get_log_v1)
        .accessory_get_v1(handler::accessory_get_v1);

    let locations = api::service::LocationsRouter::new()
        .location_get_v1(handler::location_get_v1)
        .location_create_v1(handler::locations_create_v1);

    let health = api::service::HealthRouter::new()
        .livez_list(handler::livez_list)
        .readyz_list(handler::readyz_list);

    let state: AppState = AppState {
        database,
        messagebus,
    };

    let app = axum::Router::new()
        .merge(devices)
        .merge(accessories)
        .merge(health)
        .merge(locations)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap()
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryInto,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use crate::client::error::ClientError;
    use chrono::{Utc, TimeZone};
    use uuid::uuid;

    use super::*;

    static PORT: AtomicUsize = AtomicUsize::new(8090);

    async fn run_server(
        database: Arc<super::Database>,
        messagebus: Arc<super::MessageBus>,
    ) -> Option<String> {
        let port = PORT.fetch_add(1, Ordering::SeqCst);

        tokio::spawn(super::run_server(
            database,
            messagebus,
            port.try_into().unwrap(),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Some(format!("http://127.0.0.1:{}", port))
    }

    #[tokio::test]
    async fn test_devices_list_v1_simple() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .devices_list_v1(client::devices::endpoint::DevicesListV1Query::default())
            .await;

        assert_eq!(result.is_err(), false);
        assert_eq!(result.unwrap().data.len(), 0);
    }

    #[tokio::test]
    async fn test_devices_list_v1_qs_deep_object_filter() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .devices_list_v1(client::devices::endpoint::DevicesListV1Query {
                filter: Some(client::devices::model::ListDevicesFilterQueryParameter {
                    device_id: Some("a9604d6a-3f76-476b-bfbf-97a940e879d8".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;

        assert_eq!(result.is_err(), false);
        assert_eq!(
            result.unwrap().data.get(0).unwrap().device_id,
            "a9604d6a-3f76-476b-bfbf-97a940e879d8"
        );
    }

    #[tokio::test]
    async fn test_devices_list_v1_qs_page() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .devices_list_v1(client::devices::endpoint::DevicesListV1Query {
                page: Some(2),
                ..Default::default()
            })
            .await;

        assert_eq!(result.is_err(), false);
        assert_eq!(
            result.unwrap().data.get(0).unwrap().device_id,
            "138f5d31-4feb-4765-88ad-989dff706b53"
        );
    }

    #[tokio::test]
    async fn test_devices_list_v1_qs_reserved_word() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .devices_list_v1(client::devices::endpoint::DevicesListV1Query {
                for_: Some("test".to_string()),
                ..Default::default()
            })
            .await;

        assert_eq!(result.is_err(), false);
        assert_eq!(
            result.unwrap().data.get(0).unwrap().device_id,
            "3801deea-8a6d-46cc-bc60-1e8ead00b0db"
        );
    }

    #[tokio::test]
    async fn test_accessories_get_v1_response_header() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client.accessory_get_v1("1111".to_string(), super::client::devices::endpoint::AccessoryGetV1Headers {
            secret: "test".to_string(),
        }).await;

        assert_eq!(result.is_err(), false);

        let (data, headers) = result.unwrap();

        let hash = headers.get("x-hash-key");

        assert_eq!(data.data.accessory_id, "1111".to_string());
        assert_eq!(
            hash,
            Some(&reqwest::header::HeaderValue::from_static("hash"))
        );
    }

    #[tokio::test]
    async fn test_accessories_get_v1_response_error_header() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client.accessory_get_v1("invalid".to_string(), super::client::devices::endpoint::AccessoryGetV1Headers {
            secret: "test".to_string(),
        }).await;

        assert_eq!(result.is_err(), true);

        let res = result.unwrap_err();
        if let super::client::error::ClientError::Error(
            super::client::devices::endpoint::AccessoryGetV1Error::Error400(_, headers),
        ) = res
        {
            let hash = headers.get("x-hash-key");
            assert_eq!(
                hash,
                Some(&reqwest::header::HeaderValue::from_static("hash-error"))
            );
        } else {
            panic!("Wrong response");
        }
    }

    #[tokio::test]
    async fn test_devices_get_v1_not_found() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_get_v1("missing".to_string()).await;

        let error = result.unwrap_err();
        let _expected = ClientError::Error(
            super::client::devices::endpoint::DeviceGetV1Error::Error400(
                client::devices::model::GetDevice400Response {
                    error: client::devices::model::GetDevice400ResponseError::new(
                        client::devices::model::GetDevice400ResponseErrorCodeVariant::NotFound,
                    ),
                },
            ),
        );

        assert!(matches!(error, _expected));
    }

    #[tokio::test]
    async fn test_accessory_list_v1_log() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.accessory_log_list_v1("missing".to_string()).await;
        assert_eq!(false, result.is_err());

        let data = result.unwrap();

        assert_eq!(
            "plain-text-data".to_string(),
            data.response.text().await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_device_create_v1_error_conflict() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client
            .device_create_v1(super::client::devices::model::Device::new(
                "conflict".to_string(),
                super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType15,
                uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                None,
                None,
                None,
                None,
            ))
            .await;

        assert_eq!(true, result.is_err());

        let error = result.unwrap_err();

        assert!(matches!(error, ClientError::Error(
            super::client::devices::endpoint::DeviceCreateV1Error::Error409(_),
        )));

        if let ClientError::Error(super::client::devices::endpoint::DeviceCreateV1Error::Error409(headers)) = error {
            let expected = reqwest::header::HeaderValue::from_static("/v1/devices/654");
            assert_eq!(headers.get("location"), Some(&expected));
        }


        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("location", "/v1/devices/654".parse().unwrap());
    }

    #[tokio::test]
    async fn test_device_create_v1_error_validation() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client
            .device_create_v1(super::client::devices::model::Device::new(
                "conflict".to_string(),
                super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType15,
                uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                None,
                None,
                None,
                Some("e".to_string()),
            ))
            .await;

        assert_eq!(true, result.is_err());

        let error = result.unwrap_err();

        assert!(matches!(error, ClientError::Error(
            super::client::devices::endpoint::DeviceCreateV1Error::Error400(_),
        )));
    }

    #[tokio::test]
    async fn test_accessory_create_v1_error_conflict() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client
            .accessory_create_v1(super::client::devices::model::Accessory::new(
                "conflict".to_string(),
            ))
            .await;

        assert_eq!(true, result.is_err());

        let error = result.unwrap_err();
        let _expected = ClientError::Error(
            super::client::devices::endpoint::AccessoryCreateV1Error::Error409(
                client::devices::model::AccessoryCreateError {
                    error: client::devices::model::AccessoryCreateErrorError::new(
                        client::devices::model::AccessoryCreateErrorErrorCodeVariant::ConflictError,
                    ),
                },
            ),
        );

        assert!(matches!(error, _expected));
    }

    #[tokio::test]
    async fn test_accessory_create_v1_error_validation() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client
            .accessory_create_v1(super::client::devices::model::Accessory::new(
                "error".to_string(),
            ))
            .await;

        assert_eq!(true, result.is_err());

        let error = result.unwrap_err();
        let _expected = ClientError::Error(
            super::client::devices::endpoint::AccessoryCreateV1Error::Error400(
                client::devices::model::AccessoryCreateError {
                    error: client::devices::model::AccessoryCreateErrorError::new(
                        client::devices::model::AccessoryCreateErrorErrorCodeVariant::ValidationError,
                    ),
                },
            ),
        );

        assert!(matches!(error, _expected));
    }

    #[tokio::test]
    async fn test_devices_get_v1_integer_enums_passed_as_json_numbers() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_get_v1("existing".to_string()).await;
        let device = result.unwrap();

        assert!(matches!(device.data.device_class_type, client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10));

        let serialized = serde_json::to_string(&device.data.device_class_type).unwrap();
        assert_eq!("10", serialized);
    }

    #[tokio::test]
    async fn test_devices_create_v1_simple() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
                remote_id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                updated_at: None,
                ratio: Some(10f64),
                custom: None,
                limited_text: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }
    #[tokio::test]
    async fn test_devices_create_v1_simple_date_time() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
                remote_id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                updated_at: Some(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap()),
                ratio: Some(10f64),
                custom: None,
                limited_text: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }

    #[tokio::test]
    async fn test_devices_create_v1_custom() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
                remote_id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                updated_at: Some(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap()),
                ratio: Some(10f64),
                custom: Some(Coordinates(0.5f64, 0.8f64)),
                limited_text: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }


    #[tokio::test]
    async fn test_reqwest_client() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
                remote_id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                updated_at: None,
                ratio: Some(10f64),
                custom: None,
                limited_text: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }

    #[tokio::test]
    async fn test_locations_create_v1() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        use super::client::devices::model;

        let location = model::Location {
            location_id: "test".to_string(),
            simple_mixed: Some(model::LocationSimpleMixedVariant::String("test".to_string())),
            kind_discriminator: Some(model::LocationKindDiscriminatorVariant::Simple(model::KindDiscriminatorSimpleVariant {
                name: "test".to_string(),
            })),
            kind_externally_tagged: Some(model::LocationKindExternallyTaggedVariant::Complex(
                model::LocationKindExternallyTaggedComplex{
                    name_b: "xxx".to_string(),
                }
            )),
            kind_internally_tagged: Some(model::LocationKindInternallyTaggedVariant::Complex(model::KindInternallyTaggedComplexVariant {
                name_b: "oooo".to_string(),
            })),
            kind_internally_tagged_inline: Some(model::LocationKindInternallyTaggedInlineVariant::Simple(
                model::LocationKindInternallyTaggedInlineOption1Variant {
                    name_b: "xxxx".to_string(),
                }
            )),
            un_tagged: Some(model::LocationUnTaggedVariant::KindUntaggedComplexVariant(model::KindUntaggedComplexVariant {
                name_b: "test".to_string(),
            })),
            un_tagged_mixed: Some(model::LocationUnTaggedMixedVariant::String("test".to_string())),
        };

        let original = serde_json::to_value(location.clone()).unwrap();

        let expected: serde_json::Value = serde_json::json!({
            "kindDiscriminator": {
              "name": "test",
              "testField": "simple"
            },
            "kindExternallyTagged": {
              "complex": {
                "nameB": "xxx"
              }
            },
            "kindInternallyTagged": {
              "kind": "COMPLEX",
              "nameB": "oooo"
            },
            "kindInternallyTaggedInline": {
              "kind": "SIMPLE",
              "nameB": "xxxx"
            },
            "locationId": "test",
            "simpleMixed": "test",
            "unTagged": {
              "nameB": "test"
            },
            "unTaggedMixed": "test"
          });

        // println!("original: {}", serde_json::to_string(&original).unwrap());

        assert_eq!(original, expected);

        let result = client.location_create_v1(
            location,
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap().data;

        let original = serde_json::to_value(data).unwrap();

        assert_eq!(original, expected);
    }

}
