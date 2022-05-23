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

mod api;
mod client;
mod handler {
    use std::sync::Arc;

    use axum::Extension;
    use uuid::uuid;

    use crate::{api, Database, MessageBus};

    pub async fn livez_list(db: Extension<Arc<Database>>) -> api::endpoint::LivezListResponse {
        let _result = db.get_smth().await;

        api::endpoint::LivezListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn readyz_list(db: Extension<Arc<Database>>) -> api::endpoint::ReadyzListResponse {
        let _result = db.get_smth().await;

        api::endpoint::ReadyzListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn devices_list_v1(
        query: api::endpoint::DevicesListV1Query,
        Extension(db): Extension<Arc<Database>>,
    ) -> Result<api::model::ListDevices200Response, api::model::ListDevices400Response> {
        let _result = db.get_smth().await;

        if query.for_.map(|f| f.eq("test")).unwrap_or(false) {
            return Ok(api::model::ListDevices200Response {
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
                )],
            });
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
            return Ok(api::model::ListDevices200Response {
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
                )],
            });
        } else if query.page.unwrap_or(0) == 2 {
            return Ok(api::model::ListDevices200Response {
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
                )],
            });
        }

        Ok(api::model::ListDevices200Response {
            pagination: api::model::Pagination::new(
                1,
                api::model::PaginationPageSizeVariant::PaginationPageSize10,
            ),
            data: vec![],
        })
    }

    pub async fn devices_get_v1(
        path: api::endpoint::DeviceGetV1Path,
        Extension(db): Extension<Arc<Database>>,
    ) -> api::endpoint::DeviceGetV1Response {
        let _result = db.get_smth().await;

        if path.device_id.eq("missing") {
            return api::endpoint::DeviceGetV1Response::Status400(
                api::model::GetDevice400Response {
                    error: api::model::GetDevice400ResponseError {
                        code: api::model::GetDevice400ResponseErrorCodeVariant::Notfound,
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
            ),
        })
    }

    pub async fn devices_create_v1(
        request: api::model::Device,
        Extension(db): Extension<Arc<Database>>,
        Extension(bus): Extension<Arc<MessageBus>>,
    ) -> api::endpoint::DeviceCreateV1Response {
        let _result = db.get_smth().await;
        let _result2 = bus.send().await;

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

    pub async fn devices_replace_v1(
        _path: api::endpoint::DevicePutV1Path,
        request: api::model::Device,
    ) -> api::endpoint::DevicePutV1Response {
        api::endpoint::DevicePutV1Response::Status200(
            api::model::PutDevice200Response::new(
                request
            )
        )
    }

    pub async fn accessory_create_v1(
        data: api::model::Accessory,
    ) -> api::endpoint::AccessoryCreateV1Response {
        match data.accessory_id.as_str() {
            "conflict" => api::endpoint::AccessoryCreateV1Response::Status409(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::Conflicterror,
                    },
                },
            ),
            "error" => api::endpoint::AccessoryCreateV1Response::Status400(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::Validationerror,
                    },
                },
            ),
            _ => api::endpoint::AccessoryCreateV1Response::Status400(
                api::model::AccessoryCreateError {
                    error: api::model::AccessoryCreateErrorError {
                        code: api::model::AccessoryCreateErrorErrorCodeVariant::Notfound,
                    },
                },
            ),
        }
    }

    pub async fn accessory_get_v1(
        path: api::endpoint::AccessoryGetV1Path,
        Extension(_db): Extension<Arc<Database>>,
    ) -> api::endpoint::AccessoryGetV1Response {
        if path.accessory_id == "invalid" {
            return api::endpoint::AccessoryGetV1Response::Status400(
                api::endpoint::GetAccessory400ResponseWithHeaders {
                    body: api::model::GetAccessory400Response::new(
                        api::model::GetAccessory400ResponseError {
                            code:
                                api::model::GetAccessory400ResponseErrorCodeVariant::Validationerror,
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
        _path: api::endpoint::AccessoryLogListV1Path,
        Extension(_db): Extension<Arc<Database>>,
    ) -> api::endpoint::AccessoryLogListV1Response {
        api::endpoint::AccessoryLogListV1Response::Status200("plain-text-data".to_string())
    }
}

use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() {
    let database = Arc::new(Database {});
    let messagebus = Arc::new(MessageBus {});

    run_server(database, messagebus, 8080).await
}

async fn run_server(database: Arc<Database>, messagebus: Arc<MessageBus>, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let devices = api::service::DevicesRouter::new()
        .devices_list_v1(handler::devices_list_v1)
        .device_create_v1(handler::devices_create_v1)
        .device_get_v1(handler::devices_get_v1)
        .device_put_v1(handler::devices_replace_v1);

    let accessories = api::service::AccessoriesRouter::new()
        .accessory_create_v1(handler::accessory_create_v1)
        .accessory_log_list_v1(handler::accessory_get_log_v1)
        .accessory_get_v1(handler::accessory_get_v1);

    let health = api::service::HealthRouter::new()
        .livez_list(handler::livez_list)
        .readyz_list(handler::readyz_list);

    let app = axum::Router::new()
        .merge(devices)
        .merge(accessories)
        .merge(health)
        .layer(axum::Extension(database))
        .layer(axum::Extension(messagebus));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryInto,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use crate::client::error::ClientError;
    use uuid::uuid;

    use super::*;

    static PORT: AtomicUsize = AtomicUsize::new(8080);

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

        let result = client.accessory_get_v1("1111".to_string()).await;

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

        let result = client.accessory_get_v1("invalid".to_string()).await;

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
                        client::devices::model::GetDevice400ResponseErrorCodeVariant::Notfound,
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
    async fn test_device_create_v1_enum_complex() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let device = super::client::devices::model::Device::new(
            "456".to_string(),
            super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType15,
            uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            None,
            Some(super::client::devices::model::DeviceDataVariant::DoorContainer(
                super::client::devices::model::DoorContainer::new(
                    super::client::devices::model::Door::new(
                        super::client::devices::model::DoorStateVariant::Opened,
                        "test".to_string(),
                    )
                )
            )),
        );

        let result = client
            .device_put_v1("123".to_string(), device.clone())
            .await;

        assert_eq!(
            result.unwrap(),
            super::client::devices::model::PutDevice200Response::new(device)
        );
    }

    #[tokio::test]
    async fn test_device_create_v1_enum_simple_uuid() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let device = super::client::devices::model::Device::new(
            "456".to_string(),
            super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType15,
            uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            Some(super::client::devices::model::DeviceDeviceSecretNumberVariant::Variant0(uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"))),
            None,
        );

        let result = client
            .device_put_v1("123".to_string(), device.clone())
            .await;

        assert_eq!(
            result.unwrap(),
            super::client::devices::model::PutDevice200Response::new(device)
        );
    }

    #[tokio::test]
    async fn test_device_create_v1_enum_simple_string() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let device = super::client::devices::model::Device::new(
            "456".to_string(),
            super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType15,
            uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            Some(super::client::devices::model::DeviceDeviceSecretNumberVariant::Variant1("test".to_string())),
            None,
        );

        let result = client
            .device_put_v1("123".to_string(), device.clone())
            .await;

        assert_eq!(
            result.unwrap(),
            super::client::devices::model::PutDevice200Response::new(device)
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
                        client::devices::model::AccessoryCreateErrorErrorCodeVariant::Conflicterror,
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
                        client::devices::model::AccessoryCreateErrorErrorCodeVariant::Validationerror,
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

        assert_eq!(
            device.data.device_class_type,
            client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10
        );

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
                device_secret_number: None,
                data: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }

    #[tokio::test]
    async fn test_actix_client() {
        let uri = run_server(Arc::new(Database {}), Arc::new(MessageBus {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
                remote_id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                device_secret_number: None,
                data: None,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }
}
