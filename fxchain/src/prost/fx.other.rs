#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GasPriceRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GasPriceResponse {
    #[prost(message, repeated, tag = "1")]
    pub gas_prices: ::std::vec::Vec<cosmos_sdk_proto::cosmos::base::v1beta1::Coin>,
}

#[doc = r" Generated client implementations."]
pub mod query_client {
    #![allow(unused_variables, dead_code, missing_docs)]

    use tonic::codegen::*;

    pub struct QueryClient<T> { inner: tonic::client::Grpc<T> }

    impl QueryClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error> where D: std::convert::TryInto<tonic::transport::Endpoint>, D::Error: Into<StdError>, {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> QueryClient<T> where T: tonic::client::GrpcService<tonic::body::BoxBody>, T::ResponseBody: Body + HttpBody + Send + 'static, T::Error: Into<StdError>, <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send, {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn gas_price(&mut self, request: impl tonic::IntoRequest<super::GasPriceRequest>) -> Result<tonic::Response<super::GasPriceResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| { tonic::Status::new(tonic::Code::Unknown, format!("Service was not ready: {}", e.into())) })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/fx.other.Query/GasPrice");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }

    impl<T: Clone> Clone for QueryClient<T> { fn clone(&self) -> Self { Self { inner: self.inner.clone() } } }

    impl<T> std::fmt::Debug for QueryClient<T> { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "QueryClient {{ ... }}") } }
}
