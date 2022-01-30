use actix_web::{middleware, web, App, HttpServer};
use rabbitmq::actix::{manager, producer};

pub struct Database {}

impl Database {
    pub async fn get_smth(&self) -> bool {
        true
    }
}

mod api;
mod client;
mod rabbitmq;
mod handler {
    use crate::{api, rabbitmq::actix::producer::Producer, Database};
    use actix::Addr;
    use actix_web::web;

    pub async fn livez_list(db: web::Data<Database>) -> api::endpoint::LivezListResponse {
        let _result = db.get_smth().await;

        api::endpoint::LivezListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::UP,
            components: vec![],
        })
    }

    pub async fn readyz_list(db: web::Data<Database>) -> api::endpoint::ReadyzListResponse {
        let _result = db.get_smth().await;

        api::endpoint::ReadyzListResponse::Status200(api::model::ServiceStatus {
            status: api::model::ServiceStatusStatusVariant::UP,
            components: vec![],
        })
    }

    pub async fn devices_list_v1(
        query: api::endpoint::DevicesListV1Query,
        (db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
    ) -> Result<api::model::ListDevices200Response, api::model::ListDevices400Response> {
        let _result = db.get_smth().await;

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
        }
        else if query.page.unwrap_or(0) == 2 {
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
        (db, _): (web::Data<Database>, web::Data<Addr<Producer>>),
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
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database = web::Data::new(Database {});

    run_server(database).await
}

async fn run_server(database: web::Data<Database>) -> std::io::Result<()> {
    HttpServer::new(move || {
        let manager = manager::RabbitmqManager::start("amqp://127.0.0.1:5672/%2f");

        App::new()
            .wrap(middleware::Logger::new("%a %{User-Agent}i %U"))
            .app_data(web::Data::new(producer::Producer::start(
                manager,
                "".to_string(),
            )))
            .app_data(database.clone())
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
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use crate::client::error::ClientError;

    use super::*;

    async fn run_server(database: web::Data<super::Database>) -> Option<String> {
        actix::spawn(super::run_server(database));
        // todo: chaned for waiting for port...
        actix::clock::sleep(std::time::Duration::from_millis(100)).await;
        Some("http://127.0.0.1:8080".to_string())
    }

    #[actix_web::test]
    async fn test_devices_list_v1_simple() {
        let uri = run_server(web::Data::new(Database {}))
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
        let uri = run_server(web::Data::new(Database {}))
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
        let uri = run_server(web::Data::new(Database {}))
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
    async fn test_devices_get_v1_not_found() {
        let uri = run_server(web::Data::new(Database {}))
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
    async fn test_devices_get_v1_integer_enums_passed_as_json_numbers() {
        let uri = run_server(web::Data::new(Database {}))
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
        let uri = run_server(web::Data::new(Database {}))
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
