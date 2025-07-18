# Options

## client (reqwest)

| Parameter 	 | Required 	| Default          	 | Description                                                                                                               	                                      |
|-------------|----------	|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| namespace 	 | ✔        	| 	                  | Crate name of generated client                                                                                            	                                      |
| name      	 | ✔        	| 	                  | Client name (PascalCase)                                                                                                  	                                      |
| log       	 |          	| tracing          	 | Type of logging library                                                                                                   	                                      |
| apm       	 |          	| none             	 | Apm integration, available options: tracing, tracing-opentelemetry, none                                                  	                                      |
| qs        	 |          	| serde_urlencoded 	 | Library used for query parameters, available options: serde_qs, serde_qs_1 (use serder_qs >= 1.0.0), serde_urlencoded (use serde_qs for deep  objects support) 	 |
| qs_mode   	 |          	| empty_indexed 	      | Used only when serde_qs_1 selected, available options: empty_indexed (`?a[]=1&a[]=2`), indexed (`?a[0]=1&a[1]=2`), unindexed (`?a=1&a=2`)	                         |

## server-actix

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| qs        	|          	| serde_urlencoded 	| Library used for query parameters, available options: serde_qs, serde_urlencoded (use serde_qs for deep  objects support) 	|


## server-axum

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| qs        	|          	| serde_urlencoded 	| Library used for query parameters, available options: serde_qs, serde_urlencoded (use serde_qs for deep  objects support) 	|
| extract    	|          	| axum::extract 	| Namespace of extractors                                                                                                   	|

## rabbitmq

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| client       	|          	| none          	| Type of client generated, available options: actix, none                                                                    	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| apm       	|          	| none             	| Apm integration, available options: tracing, tracing-opentelemetry, none                                                  	|
