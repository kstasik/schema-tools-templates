use actix_web::{middleware, web, App, HttpServer};
use rabbitmq::actix::{manager, producer};

pub struct Database {}

impl Database {
    pub async fn get_smth(&self) -> bool {
        true
    }
}

pub struct Repository {}

impl Repository {
    pub async fn get_smth(&self) -> bool {
        true
    }
}

mod api;
mod client;
mod rabbitmq;
mod handler {
    use crate::{api, rabbitmq::actix::producer::Producer, Database, Repository};
    use actix::Addr;
    use actix_web::web;

    pub async fn livez_list(db: web::Data<Database>) -> api::endpoint::LivezListResponse {
        let _result = db.get_smth().await;

        api::endpoint::LivezListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn readyz_list(db: web::Data<Database>) -> api::endpoint::ReadyzListResponse {
        let _result = db.get_smth().await;

        api::endpoint::ReadyzListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::Up,
            components: vec![],
        })
    }

    pub async fn devices_list_v1(
        query: api::endpoint::DevicesListV1Query,
        (db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> Result<api::model::ListDevices200Response, api::model::ListDevices400Response> {
        let _result = db.get_smth().await;

        if query.for_.map(|f| f.eq("test")).unwrap_or(false) {
            return Ok(api::model::ListDevices200Response {
                data: vec![api::model::Device::new(
                    "3801deea-8a6d-46cc-bc60-1e8ead00b0db".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
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
                data: vec![api::model::Device::new(
                    "a9604d6a-3f76-476b-bfbf-97a940e879d8".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                )],
            });
        } else if query.page.unwrap_or(0) == 2 {
            return Ok(api::model::ListDevices200Response {
                data: vec![api::model::Device::new(
                    "138f5d31-4feb-4765-88ad-989dff706b53".to_string(),
                    api::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType10,
                )],
            });
        }

        Ok(api::model::ListDevices200Response { data: vec![] })
    }

    pub async fn devices_get_v1(
        path: api::endpoint::DeviceGetV1Path,
        (db, _, _repository): (web::Data<Database>, web::Data<Addr<Producer>>, web::Data<Repository>),
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
            ),
        })
    }

    pub async fn devices_create_v1(
        _request: api::model::Device,
        (db, _producer): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> api::endpoint::DeviceCreateV1Response {
        let _result = db.get_smth().await;

        api::endpoint::DeviceCreateV1Response::Status201
    }

    pub async fn accessory_create_v1(
        data: api::model::Accessory,
        (_db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> api::endpoint::AccessoryCreateV1Response {
        match data.accessory_id.as_str() {
            "conflict" => api::endpoint::AccessoryCreateV1Response::Status409(api::model::AccessoryCreateError {
                error: api::model::AccessoryCreateErrorError{
                    code: api::model::AccessoryCreateErrorErrorCodeVariant::Conflicterror,
                },
            }),
            "error" => api::endpoint::AccessoryCreateV1Response::Status400(api::model::AccessoryCreateError {
                error: api::model::AccessoryCreateErrorError{
                    code: api::model::AccessoryCreateErrorErrorCodeVariant::Validationerror,
                },
            }),
            _ => api::endpoint::AccessoryCreateV1Response::Status400(api::model::AccessoryCreateError {
                error: api::model::AccessoryCreateErrorError{
                    code: api::model::AccessoryCreateErrorErrorCodeVariant::Notfound,
                },
            })
        }
    }
    
    pub async fn accessory_get_v1(
        path: api::endpoint::AccessoryGetV1Path,
        (_db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> api::endpoint::AccessoryGetV1Response {
        if path.accessory_id == "invalid" {
            return api::endpoint::AccessoryGetV1Response::Status400(api::endpoint::GetAccessory400ResponseWithHeaders{
                body: api::model::GetAccessory400Response::new(
                    None,
                ),
                headers: api::endpoint::AccessoryGetV1Response400Headers{
                    x_hash_key: "hash-error".to_string(),
                }
            });
        }

        api::endpoint::AccessoryGetV1Response::Status200(api::endpoint::GetAccessory200ResponseWithHeaders{
            body: api::model::GetAccessory200Response::new(
                api::model::Accessory::new(path.accessory_id),
            ),
            headers: api::endpoint::AccessoryGetV1Response200Headers{
                x_hash_key: "hash".to_string(),
            }
        })
    }

    pub async fn accessory_get_log_v1(
        _path: api::endpoint::AccessoryLogListV1Path,
        (_db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> api::endpoint::AccessoryLogListV1Response {
        api::endpoint::AccessoryLogListV1Response::Status200("plain-text-data".to_string())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database = web::Data::new(Database {});
    let repository = web::Data::new(Repository {});

    run_server(database, repository).await
}

async fn run_server(database: web::Data<Database>, repository: web::Data<Repository>) -> std::io::Result<()> {
    HttpServer::new(move || {
        let manager = manager::RabbitmqManager::start("amqp://127.0.0.1:5672/%2f");

        App::new()
            .wrap(middleware::Logger::new("%a %{User-Agent}i %U"))
            .app_data(web::Data::new(producer::Producer::start(
                manager,
                "".to_string(),
            )))
            .app_data(database.clone())
            .app_data(repository.clone())
            // enable logger
            .wrap(middleware::Logger::default())
            .configure(api::service::configure_health(
                handler::livez_list,
                handler::readyz_list,
            ))
            .configure(api::service::configure_devices(
                handler::devices_list_v1,
                handler::devices_create_v1,
                handler::devices_get_v1,
            ))
            .configure(api::service::configure_accessories(
                handler::accessory_create_v1,
                handler::accessory_get_v1,
                handler::accessory_get_log_v1,
            ))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use crate::client::error::ClientError;

    use super::*;

    async fn run_server(database: web::Data<super::Database>, repository: web::Data<super::Repository>) -> Option<String> {
        actix::spawn(super::run_server(database, repository));
        // todo: chaned for waiting for port...
        actix::clock::sleep(std::time::Duration::from_millis(100)).await;
        Some("http://127.0.0.1:8080".to_string())
    }

    #[actix_web::test]
    async fn test_devices_list_v1_simple() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_devices_list_v1_qs_deep_object_filter() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_devices_list_v1_qs_page() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_devices_list_v1_qs_reserved_word() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_accessories_get_v1_response_header() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .accessory_get_v1("1111".to_string())
            .await;

        assert_eq!(result.is_err(), false);

        let (data, headers) = result.unwrap();

        let hash = headers.get("x-hash-key");

        assert_eq!(data.data.accessory_id, "1111".to_string());
        assert_eq!(hash, Some(&reqwest::header::HeaderValue::from_static("hash")));
    }

    #[actix_web::test]
    async fn test_accessories_get_v1_response_error_header() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new())
            .with_auth_basic_auth("testing");

        let result = client
            .accessory_get_v1("invalid".to_string())
            .await;

        assert_eq!(result.is_err(), true);

        let res = result.unwrap_err();
        if let super::client::error::ClientError::Error(super::client::devices::endpoint::AccessoryGetV1Error::Error400(_, headers)) = res {
            let hash = headers.get("x-hash-key");
            assert_eq!(hash, Some(&reqwest::header::HeaderValue::from_static("hash-error")));
        } else {
            panic!("Wrong response");
        }
    }

    #[actix_web::test]
    async fn test_devices_get_v1_not_found() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_accessory_list_v1_log() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.accessory_log_list_v1("missing".to_string()).await;
        assert_eq!(false, result.is_err());

        let data = result.unwrap();

        assert_eq!("plain-text-data".to_string(), data.response.text().await.unwrap());
    }

    #[actix_web::test]
    async fn test_accessory_create_v1_error_conflict() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.accessory_create_v1(super::client::devices::model::Accessory::new(
            "conflict".to_string(),
        )).await;

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

    #[actix_web::test]
    async fn test_accessory_create_v1_error_validation() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.accessory_create_v1(super::client::devices::model::Accessory::new(
            "error".to_string(),
        )).await;

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

    #[actix_web::test]
    async fn test_devices_get_v1_integer_enums_passed_as_json_numbers() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
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

    #[actix_web::test]
    async fn test_devices_create_v1_simple() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }

    #[actix_web::test]
    async fn test_actix_client() {
        let uri = run_server(web::Data::new(Database {}), web::Data::new(Repository {}))
            .await
            .expect("Cannot run server");

        let client = super::client::devices::DevicesClient::new(uri, reqwest::Client::new());

        let result = client.device_create_v1(
            super::client::devices::model::Device {
                device_id: "test".to_string(),
                device_class_type: super::client::devices::model::DeviceDeviceClassTypeVariant::DeviceDeviceClassType20,
            }
        ).await;

        assert_eq!(result.is_err(), false);

        let data = result.unwrap();

        assert_eq!(data.response.status().as_u16(), 201);
    }
}
