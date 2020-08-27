package burp;

import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

public class BurpExtender implements IBurpExtender, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private ArrayList<URL> previouslyAnalyzedURLs;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Private Node Module Finder");
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.previouslyAnalyzedURLs = new ArrayList<URL>();
		callbacks.registerHttpListener(this);
	}

	public ArrayList<String> findModules(String responseBody) {
		// Look at all enclosed strings in body and extract module name
		ArrayList<String> moduleNames = new ArrayList<String>();

		String nodeModulesString = "node_modules/";
		for (String line : responseBody.split("\n")) {
			int nodeModulesIndex = line.indexOf(nodeModulesString);
			while (nodeModulesIndex >= 0) {
				int nodeModulesEndIndex = line.indexOf(nodeModulesString) + nodeModulesString.length();

				if (nodeModulesEndIndex <= line.length()) {
					int nextSlashIndex = line.indexOf("/", nodeModulesEndIndex);

					if (nextSlashIndex >= 0) {
						String moduleName = line.substring(nodeModulesEndIndex, nextSlashIndex);
						if (!moduleNames.contains(moduleName)) {
							moduleNames.add(moduleName);
						}
					}

					line = line.substring(nodeModulesEndIndex);
				}
				nodeModulesIndex = line.indexOf(nodeModulesString);
			}
		}

		return moduleNames;
	}

	// Requests https://registry.npmjs.org/<module_name> and return true if status
	// code is 200
	private boolean isNodeModulePublic(String moduleName) {
		final String PUBLIC_NODE_REGISTRY_URL_STRING = "registry.npmjs.org";
		String publicNodeModuleUrlString = String.format("https://%s/%s", PUBLIC_NODE_REGISTRY_URL_STRING, moduleName);

		try {
			URL url = new URL(publicNodeModuleUrlString);
			HttpURLConnection http = (HttpURLConnection) url.openConnection();
			int statusCode = http.getResponseCode();
			return statusCode == 200;
		} catch (Exception e) {
			this.stdout.println("Failed to make request to '" + publicNodeModuleUrlString + "': " + e.getMessage());
		}

		return false;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// Determine the URL we're looking at
		IHttpService httpService = messageInfo.getHttpService();
		byte[] requestBytes = messageInfo.getRequest();
		IRequestInfo requestInfo = this.helpers.analyzeRequest(httpService, requestBytes);
		URL url = requestInfo.getUrl();

		// Determine if we've already analyzed this URL
		boolean alreadyAnalyzed = false;
		for (URL previousURL : this.previouslyAnalyzedURLs) {
			if (url.sameFile(previousURL)) {
				alreadyAnalyzed = true;
			}
		}

		if (!alreadyAnalyzed) {
			// Compute the HTTP response body
			byte[] responseBytes = messageInfo.getResponse();
			IResponseInfo responseInfo = this.helpers.analyzeResponse(responseBytes);
			int responseBodyOffset = responseInfo.getBodyOffset();
			byte[] bodyBytes = Arrays.copyOfRange(responseBytes, responseBodyOffset, responseBytes.length);
			String bodyString = this.helpers.bytesToString(bodyBytes);

			// Find and show modules to user
			ArrayList<String> moduleNames = findModules(bodyString);

			// Verify if any of the mentioned modules aren't public. If so, report it.
			for (String moduleName : moduleNames) {
				if (!isNodeModulePublic(moduleName)) {
					this.stdout.println("'" + url.toString() + "' | Private module found: " + moduleName);

					// TODO: Add highlighting like in:
					// https://github.com/PortSwigger/example-scanner-checks/blob/master/java/BurpExtender.java
					IHttpRequestResponse[] messageInfoArray = new IHttpRequestResponse[] { messageInfo };
					PrivateNodeModuleScanIssue issue = new PrivateNodeModuleScanIssue(httpService, url, messageInfoArray, moduleName);
					callbacks.addScanIssue(issue);
				}
			}

			// Add to list so we don't analyze again
			if (!this.previouslyAnalyzedURLs.contains(url)) {
				this.previouslyAnalyzedURLs.add(url);
			}
		}
	}
}
