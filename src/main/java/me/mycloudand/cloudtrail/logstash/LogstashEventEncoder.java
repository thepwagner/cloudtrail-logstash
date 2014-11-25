package me.mycloudand.cloudtrail.logstash;

import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEvent;
import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEventData;
import com.amazonaws.services.cloudtrail.processinglibrary.model.internal.CloudTrailDataStore;

/**
 * Encodes CloudTrail events in Logstash 1.2 format.
 * <p/>
 * Based on https://github.com/logstash/log4j-jsonevent-layout , couldn't find a "this is the schema" page anywhere.
 */
public class LogstashEventEncoder
{
	private final String type;
	private final SimpleDateFormat timestampFormat;
	private final Field dataStoreField;

	/**
	 * Constructor.
	 *
	 * @param type
	 *            Event type.
	 */
	public LogstashEventEncoder(String type)
	{
		this.type = type;
		timestampFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		timestampFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

		try
		{
			dataStoreField = CloudTrailDataStore.class.getDeclaredField("dataStore");
			dataStoreField.setAccessible(true);
		}
		catch (NoSuchFieldException e)
		{
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Encode an event as Logstash JSON object.
	 *
	 * @param cloudTrailEvent
	 *            Cloud trail event.
	 * @return Logstash JSON object.
	 */
	public Map<String, Object> encodeEvent(CloudTrailEvent cloudTrailEvent)
	{
		CloudTrailEventData eventData = cloudTrailEvent.getEventData();

		try
		{
			// We _really_ want the Map view of the event:
			Map<String, Object> eventDataMap = (Map<String, Object>)dataStoreField.get(eventData);

			// Customize payload for logstash:
			eventDataMap.put("@version", 1);
			eventDataMap.put("@timestamp", dateFormat(eventData.getEventTime()));
			if (type != null)
			{
				eventDataMap.put("type", type);
			}
			return eventDataMap;
		}
		catch (IllegalAccessException e)
		{
			throw new IllegalStateException(e);
		}
	}

	private synchronized String dateFormat(Date timestamp)
	{
		return timestampFormat.format(timestamp);
	}
}
