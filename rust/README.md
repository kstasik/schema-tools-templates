# Options

## client (reqwest)

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| namespace 	| ✔        	|                  	| Crate name of generated client                                                                                            	|
| name      	| ✔        	|                  	| Client name (PascalCase)                                                                                                  	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| apm       	|          	| none             	| Apm integration, available options: tracing, tracing-opentelemetry, none                                                  	|
| qs        	|          	| serde_urlencoded 	| Library used for query parameters, available options: serde_qs, serde_urlencoded (use serde_qs for deep  objects support) 	|

## server-actix

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| qs        	|          	| serde_urlencoded 	| Library used for query parameters, available options: serde_qs, serde_urlencoded (use serde_qs for deep  objects support) 	|

## rabbitmq

| Parameter 	| Required 	| Default          	| Description                                                                                                               	|
|-----------	|----------	|------------------	|---------------------------------------------------------------------------------------------------------------------------	|
| client       	|          	| none          	| Type of client generated, available options: actix, none                                                                    	|
| log       	|          	| tracing          	| Type of logging library                                                                                                   	|
| apm       	|          	| none             	| Apm integration, available options: tracing, tracing-opentelemetry, none                                                  	|
