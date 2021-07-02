#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;

use hyper::{Body, Server};
use hyper::http::{Request, Response};
use hyper::http::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use lazy_static::lazy_static;
use prometheus::{Counter, Encoder, Gauge, HistogramVec, TextEncoder};

pub mod metrics;

lazy_static! {
    static ref HTTP_COUNTER: Counter = register_counter!(opts!(
        "http_requests_total",
        "Number of HTTP requests made."
    ))
    .unwrap();
    static ref HTTP_BODY_GAUGE: Gauge = register_gauge!(opts!(
        "http_response_size_bytes",
        "The HTTP response sizes in bytes."
    ))
    .unwrap();
    static ref HTTP_REQ_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["chain_id"]
    )
    .unwrap();
}

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();

    HTTP_COUNTER.inc();
    let timer = HTTP_REQ_HISTOGRAM.with_label_values(&["all"]).start_timer();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    HTTP_BODY_GAUGE.set(buffer.len() as f64);

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();

    timer.observe_duration();

    Ok(response)
}

pub async fn start(port: u16) {
    let addr = ([0, 0, 0, 0], port).into();
    info!("Prometheus Listening on http://{}", addr);
    let serve_future = Server::bind(&addr).serve(make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(serve_req))
    }));
    if let Err(err) = serve_future.await {
        panic!("Prometheus server error: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter::Info;

    use super::*;

    #[tokio::test]
    async fn test_prometheus() {
        env_logger::builder().filter_level(Info).init();
        start(9898).await
    }
}
