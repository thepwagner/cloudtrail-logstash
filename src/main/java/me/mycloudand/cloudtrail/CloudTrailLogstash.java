package me.mycloudand.cloudtrail;

import com.amazonaws.services.cloudtrail.processinglibrary.AWSCloudTrailProcessingExecutor;
import com.amazonaws.services.cloudtrail.processinglibrary.configuration.ProcessingConfiguration;

/**
 * Entry point.
 */
public class CloudTrailLogstash
{
	public static void main(String[] args)
	{
		CliOptions cliOptions = new CliOptions();
		cliOptions.parse(args);

		RedisEventsProcessor eventsProcessor = new RedisEventsProcessor(cliOptions);
		ProcessingConfiguration processingConfiguration = cliOptions.getProcessingConfiguration();
		AWSCloudTrailProcessingExecutor executor = new AWSCloudTrailProcessingExecutor.Builder(eventsProcessor, processingConfiguration)
				.build();
		executor.start();
	}
}
