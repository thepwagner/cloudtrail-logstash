package me.mycloudand.cloudtrail;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import me.mycloudand.cloudtrail.logstash.LogstashEventEncoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.exceptions.JedisConnectionException;

import com.amazonaws.services.cloudtrail.processinglibrary.exceptions.CallbackException;
import com.amazonaws.services.cloudtrail.processinglibrary.interfaces.EventsProcessor;
import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Serialize events and push to Redis.
 */
public class RedisEventsProcessor implements EventsProcessor
{
	private static final Logger log = LoggerFactory.getLogger(RedisEventsProcessor.class);

	private final LogstashEventEncoder logstashEventEncoder;
	private final ObjectMapper mapper;
	private final JedisPool jedisPool;
	private final String redisKey;
	private final boolean batchWrite;
	private final int maxAttempts;

	/**
	 * Constructor.
	 * 
	 * @param options
	 *            Parsed options.
	 */
	public RedisEventsProcessor(CliOptions options)
	{
		mapper = new ObjectMapper();
		logstashEventEncoder = new LogstashEventEncoder(options.getType());
		jedisPool = new JedisPool(options.getRedisURI());
		redisKey = options.getRedisKey();
		batchWrite = options.isBatchWrite();
		maxAttempts = options.getMaxRetries();
	}

	@Override
	public void process(List<CloudTrailEvent> events) throws CallbackException
	{
		if (batchWrite)
		{
			writeBatch(events);
		}
		else
		{
			writeSerial(events);
		}
	}

	private void writeBatch(List<CloudTrailEvent> events)
	{
		List<String> jsonEvents = new ArrayList<>(events.size());
		for (CloudTrailEvent event : events)
		{
			Map<String, Object> logstashEvent = logstashEventEncoder.encodeEvent(event);
			try
			{
				String jsonEvent = mapper.writeValueAsString(logstashEvent);
				jsonEvents.add(jsonEvent);
			}
			catch (JsonProcessingException e)
			{
				log.warn("Serialization error", e);
			}
		}

		rpush(jsonEvents.toArray(new String[0]));
	}

	private void writeSerial(List<CloudTrailEvent> events)
	{
		for (CloudTrailEvent event : events)
		{
			Map<String, Object> logstashEvent = logstashEventEncoder.encodeEvent(event);
			try
			{
				String jsonEvent = mapper.writeValueAsString(logstashEvent);
				rpush(jsonEvent);
				break;
			}
			catch (JsonProcessingException e)
			{
				log.warn("Serialization error", e);
			}
		}
	}

	private void rpush(String... jsonEvents)
	{
		int attempt = 0;
		for (; attempt < maxAttempts; attempt++)
		{
			Jedis jedis = null;
			try
			{
				jedis = jedisPool.getResource();
				jedis.rpush(redisKey, jsonEvents);
				return;
			}
			catch (JedisConnectionException e)
			{
				log.warn("Error communicating with Jedis", e);
				jedisPool.returnBrokenResource(jedis);
				backoff(attempt);
			}
			finally
			{
				jedisPool.returnResource(jedis);
			}
		}

		if (attempt == maxAttempts)
		{
			throw new IllegalStateException("Unable to store event in Redis.");
		}
	}

	private void backoff(int attempt)
	{
		long sleepTime = Double.valueOf(Math.pow(2, attempt)).longValue() * 1000;
		try
		{
			Thread.sleep(sleepTime);
		}
		catch (InterruptedException e2)
		{
		}
	}
}
