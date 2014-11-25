package me.mycloudand.cloudtrail;

import java.net.URI;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cloudtrail.processinglibrary.configuration.ClientConfiguration;
import com.amazonaws.services.cloudtrail.processinglibrary.configuration.ProcessingConfiguration;

/**
 * Parses command line.
 */
public class CliOptions
{
	private static final Logger log = LoggerFactory.getLogger(CliOptions.class);

	// AWS parameters:
	private static final String AWS_ACCESS_KEY = "accessKey";
	private static final String AWS_SECRET_KEY = "secretKey";
	private static final String S3_REGION = "s3Region";
	private static final String SQS_REGION = "sqsRegion";
	private static final String SQS_URL = "sqsUrl";
	private Regions s3Region;
	private Regions sqsRegion;
	private String awsAccessKey;
	private String awsSecretKey;
	private String sqsUrl;

	// Logstash customizations:
	private static final String LOGSTASH_TYPE = "type";
	private static final String LOGSTASH_TYPE_DEFAULT = "cloudtrail";
	private String type;

	// Redis backend:
	private static final String REDIS_URI = "redisUri";
	private static final String REDIS_URI_DEFAULT = "redis://localhost:6379/0";
	private static final String REDIS_KEY = "redisKey";
	private static final String REDIS_KEY_DEFAULT = "logstash";
	private static final String REDIS_BATCH = "redisBatch";
	private static final String MAX_RETRIES = "redisRetries";
	private static final String MAX_RETRIES_DEFAULT = "5";
	private URI redisURI;
	private String redisKey;
	private boolean batchWrite;
	private int maxRetries;

	private final Options options;

	public CliOptions()
	{
		options = new Options();

		options.addOption(new Option(AWS_ACCESS_KEY, true, "AWS access key, defaults to environment variables + IAM role"));
		options.addOption(new Option(AWS_SECRET_KEY, true, "AWS secret key, defaults to environment variables + IAM role"));
		options.addOption(new Option(S3_REGION, true, "Region for S3 operations."));
		options.addOption(new Option(SQS_REGION, true, "Region for SQS operations."));
		options.addOption(new Option(SQS_URL, true, "URL for SQS (required)."));

		options.addOption(new Option(LOGSTASH_TYPE, true, "Value for event \"type\" field, default: " + LOGSTASH_TYPE_DEFAULT));

		options.addOption(new Option(REDIS_URI, true, "URI for redis, default: " + REDIS_URI_DEFAULT));
		options.addOption(new Option(REDIS_KEY, true, "Key for redis, default: " + REDIS_KEY_DEFAULT));
		options.addOption(new Option(REDIS_BATCH, false, "Write events to redis serially or batched (default serial)"));
		options.addOption(new Option(MAX_RETRIES, true, "The maximum number of retries for redis, default:" + MAX_RETRIES_DEFAULT));
	}

	/**
	 * Parse arguments, updating state.
	 * 
	 * @param arguments
	 *            Arguments.
	 */
	public void parse(String[] arguments)
	{
		CommandLine commandLine;
		try
		{
			CommandLineParser parser = new GnuParser();
			commandLine = parser.parse(options, arguments);
		}
		catch (ParseException e)
		{
			log.warn("Error parsing command line", e);
			printHelp();
			return;
		}

		awsAccessKey = commandLine.getOptionValue(AWS_ACCESS_KEY);
		awsSecretKey = commandLine.getOptionValue(AWS_SECRET_KEY);
		sqsUrl = commandLine.getOptionValue(SQS_URL);
		s3Region = getRegionArgument(commandLine, S3_REGION);
		sqsRegion = getRegionArgument(commandLine, SQS_REGION);

		if (sqsUrl == null)
		{
			printHelp();
			throw new IllegalStateException("SQS URI required, " + sqsUrl + " is not valid.");
		}

		type = commandLine.getOptionValue(LOGSTASH_TYPE, LOGSTASH_TYPE_DEFAULT);

		String redisUriRaw = commandLine.getOptionValue(REDIS_URI, REDIS_URI_DEFAULT);
		redisURI = URI.create(redisUriRaw);
		if (redisURI == null)
		{
			printHelp();
			throw new IllegalStateException("Redis URI required, " + redisUriRaw + " is not valid.");
		}
		redisKey = commandLine.getOptionValue(REDIS_KEY, REDIS_KEY_DEFAULT);
		batchWrite = commandLine.hasOption(REDIS_BATCH);
		String maxRetriesRaw = commandLine.getOptionValue(MAX_RETRIES, MAX_RETRIES_DEFAULT);
		maxRetries = Integer.valueOf(maxRetriesRaw);
	}

	private void printHelp()
	{
		HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.printHelp("cloudtrail-logstash", options);
	}

	private Regions getRegionArgument(CommandLine commandLine, String regionArgument)
	{
		String optionValue = commandLine.getOptionValue(S3_REGION);
		if (optionValue == null)
		{
			return null;
		}
		return Regions.fromName(optionValue);
	}

	public ProcessingConfiguration getProcessingConfiguration()
	{
		AWSCredentialsProvider creds = getAwsCredentialsProvider();

		ClientConfiguration clientConfiguration = new ClientConfiguration(sqsUrl, creds);
		if (s3Region != null)
		{
			clientConfiguration.setS3Region(s3Region.getName());
		}

		if (sqsRegion != null)
		{
			clientConfiguration.setSqsRegion(sqsRegion.getName());
		}
		return clientConfiguration;
	}

	public String getType()
	{
		return type;
	}

	public URI getRedisURI()
	{
		return redisURI;
	}

	public String getRedisKey()
	{
		return redisKey;
	}

	public boolean isBatchWrite()
	{
		return batchWrite;
	}

	public int getMaxRetries()
	{
		return maxRetries;
	}

	private AWSCredentialsProvider getAwsCredentialsProvider()
	{
		AWSCredentialsProvider creds;
		if (awsAccessKey != null && awsSecretKey != null)
		{
			final AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
			creds = new AWSCredentialsProvider() {
				@Override
				public AWSCredentials getCredentials()
				{
					return credentials;
				}

				@Override
				public void refresh()
				{
				}
			};
		}
		else
		{
			creds = new DefaultAWSCredentialsProviderChain();
		}
		return creds;
	}
}
