/*
 * Copyright (c) 2025 Sam Packer
 *
 * This software is licensed under the PolyForm Noncommercial License 1.0.0.
 *
 * You may use, copy, modify, and distribute this software for noncommercial purposes only.
 * Commercial use of this software, in whole or in part, is prohibited.
 *
 * See the full license text at:
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 * or in the LICENSE.md file included with this source code.
 */

package com.sampacker.shibboleth.rba;

import com.google.gson.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.*;

import static com.sampacker.shibboleth.rba.utils.StringHelper.readAll;

/**
 * Thread-safe cache that periodically fetches GET /models and maintains
 * a mapping of model version to threshold.
 */
public class ModelRegistryCache
{

    private static final Gson GSON = new GsonBuilder().create();
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    private final Logger log = LoggerFactory.getLogger(ModelRegistryCache.class);

    private final String modelsEndpoint;
    private final int refreshIntervalSeconds;
    private final ConcurrentHashMap<Integer, Double> cache = new ConcurrentHashMap<>();
    private ScheduledExecutorService executor;

    public ModelRegistryCache(String modelsEndpoint, int refreshIntervalSeconds)
    {
        this.modelsEndpoint = modelsEndpoint;
        this.refreshIntervalSeconds = refreshIntervalSeconds;
    }

    public void start()
    {
        refresh();
        executor = Executors.newSingleThreadScheduledExecutor(r ->
        {
            Thread t = new Thread(r, "ModelRegistryCache-refresh");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleAtFixedRate(this::refresh, refreshIntervalSeconds, refreshIntervalSeconds, TimeUnit.SECONDS);
    }

    public void stop()
    {
        if (executor != null)
        {
            executor.shutdownNow();
        }
    }

    /**
     * Returns the threshold for a specific model version, or null if not cached.
     */
    public Double getThreshold(int modelVersion)
    {
        return cache.get(modelVersion);
    }

    /**
     * Returns the threshold for the highest version number with a non-null threshold,
     * or null if the cache is empty.
     */
    public Double getLatestThreshold()
    {
        return cache.entrySet().stream()
                .max(java.util.Map.Entry.comparingByKey())
                .map(java.util.Map.Entry::getValue)
                .orElse(null);
    }

    /**
     * Submits a one-off refresh task for cache-miss scenarios.
     */
    public void triggerAsyncRefresh()
    {
        if (executor != null && !executor.isShutdown())
        {
            executor.submit(this::refresh);
        }
    }

    /**
     * Performs a synchronous refresh of the cache.
     * Used for cache-miss retry flow where the caller needs updated data immediately.
     */
    public void refreshNow()
    {
        refresh();
    }

    /**
     * Fetches /models, parses the JSON response, and updates the cache.
     * On failure, logs a warning and retains previous cache (never clears on error).
     */
    void refresh()
    {
        HttpURLConnection conn = null;
        try
        {
            final URL url = new URL(modelsEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            final int status = conn.getResponseCode();
            final boolean ok = status >= 200 && status < 300;
            final String body = readAll(ok ? conn.getInputStream() : conn.getErrorStream());

            if (!ok)
            {
                log.warn("Models endpoint returned non-2xx status: {}. Retaining previous cache.", status);
                return;
            }

            final JsonObject responseObj = GSON.fromJson(body, JsonObject.class);
            if (responseObj == null || !responseObj.has("models"))
            {
                log.warn("Models endpoint response missing 'models' key. Retaining previous cache.");
                return;
            }
            final JsonArray models = responseObj.getAsJsonArray("models");
            if (models == null || models.isEmpty())
            {
                log.info("Models endpoint returned empty models array. Clearing cache (data collection mode).");
                cache.clear();
                return;
            }

            ConcurrentHashMap<Integer, Double> newEntries = new ConcurrentHashMap<>();
            for (JsonElement element : models)
            {
                if (!element.isJsonObject())
                {
                    continue;
                }
                JsonObject model = element.getAsJsonObject();
                if (!model.has("version"))
                {
                    continue;
                }
                int version = model.get("version").getAsInt();
                if (!model.has("anomaly_threshold") || model.get("anomaly_threshold").isJsonNull())
                {
                    continue;
                }
                double threshold = model.get("anomaly_threshold").getAsDouble();
                if (Double.isFinite(threshold))
                {
                    newEntries.put(version, threshold);
                }
            }

            if (newEntries.isEmpty())
            {
                log.warn("No valid model entries with thresholds found. Retaining previous cache.");
                return;
            }

            cache.clear();
            cache.putAll(newEntries);
            log.debug("Model cache refreshed with {} entries.", newEntries.size());
        }
        catch (Exception e)
        {
            log.warn("Failed to refresh model cache from {}. Retaining previous cache.", modelsEndpoint, e);
        }
        finally
        {
            if (conn != null)
            {
                conn.disconnect();
            }
        }
    }

    /**
     * Returns true if the cache has no entries.
     */
    public boolean isEmpty()
    {
        return cache.isEmpty();
    }
}
