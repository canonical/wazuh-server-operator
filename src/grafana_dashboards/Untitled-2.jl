rate(wazuh_active_agents[5m])/rate(wazuh_total_agents[5m])
rate(wazuh_disconnected_agents[5m])/rate(wazuh_total_agents[5m])
rate(wazuh_never_connected_agents[5m])/rate(wazuh_total_agents[5m])
rate(wazuh_pending_agents[5m])/rate(wazuh_total_agents[5m])


wazuh_validate_configuration_info



rate(analysisd_stats{analysisd_stats="events_processed"}[5m])/rate(analysisd_stats{analysisd_stats="events_received"}[5m])
rate(analysisd_stats{analysisd_stats="events_dropped"}[5m])/(analysisd_stats{analysisd_stats="events_received"}[5m])

rate(analysisd_stats{analysisd_stats="event_queue_usage"}[5m])/rate(analysisd_stats{analysisd_stats="event_queue_size"}[5m])
rate(analysisd_stats{analysisd_stats="alerts_queue_usage"}[5m])/rate(analysisd_stats{analysisd_stats="alerts_queue_size"}[5m])

increase(analysisd_stats{analysisd_stats="alerts_written"}[5m])
