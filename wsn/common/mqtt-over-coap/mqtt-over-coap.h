#pragma once

bool
mqtt_over_coap_publish(const char* topic, const void* data, size_t data_len);
