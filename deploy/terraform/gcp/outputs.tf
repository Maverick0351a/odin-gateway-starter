output "gateway_url" {
	value = google_cloud_run_service.gateway.status[0].url
	description = "Public URL of the deployed Cloud Run gateway"
}
