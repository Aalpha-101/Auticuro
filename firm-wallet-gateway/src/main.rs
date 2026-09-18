#![allow(clippy::new_without_default)]
use airwallex_webhook::AirwallexWebhookServer;
/**
 * Copyright 2022 Airwallex (Hong Kong) Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 *
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
use dotenv::dotenv;
use firm_wallet_gateway::Node;
use gateway_framework::gateway::Gateway;
use hologram_protos::firm_wallet::account_management_servicepb::account_management_service_server::AccountManagementServiceServer;
use hologram_protos::firm_wallet::balance_operation_servicepb::balance_operation_service_server::BalanceOperationServiceServer;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::{info, Level};

pub mod airwallex_webhook;
pub mod firm_wallet_gateway;

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    dotenv().ok();

    let gateway_service = Gateway::<Node>::new();
    let grpc_address = get_server_address();
    let webhook_server =
        AirwallexWebhookServer::from_env().expect("Failed to configure Airwallex webhook server");

    info!(
        "Firm wallet gateway service listen on address: {}",
        grpc_address
    );

    tokio::try_join!(
        async move {
            Server::builder()
                .add_service(BalanceOperationServiceServer::new(gateway_service.clone()))
                .add_service(AccountManagementServiceServer::new(gateway_service))
                .serve(grpc_address)
                .await
                .map_err(|error| -> BoxError { Box::new(error) })
        },
        async move {
            webhook_server
                .serve()
                .await
                .map_err(|error| -> BoxError { Box::new(error) })
        }
    )
    .unwrap();
}

pub fn get_server_address() -> SocketAddr {
    let port = env::var("GATEWAY_SERVICE_PORT").unwrap_or_else(|_| "20221".to_string());
    let address = format!("0.0.0.0:{}", port);
    address.parse::<SocketAddr>().unwrap_or_else(|e| {
        panic!(
            "Failed to parse server address {} with error :{}",
            address, e
        )
    })
}
