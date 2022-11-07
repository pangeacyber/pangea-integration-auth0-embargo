exports.onExecutePostLogin = async (event, api) => {
	  const Pangea = require('node-pangea');
	  const domain = "aws.us.pangea.cloud";
	  const token = event.secrets.TOKEN;
	  const configId = event.configuration.CONFIGID;
	  const config = new Pangea.PangeaConfig({ domain: domain, configId: configId });
	  const audit = new Pangea.AuditService(token, config);
	  const embargo = new Pangea.EmbargoService(token, config);
	  
	  const ip = event.request.ip;
	  let context = {
		      "connection":event.connection,
		      "request":event.request,
		      "user":event.user
		      };
	  let data = {
		      "actor": event.user.email,
		      "action": "Embargo Check",
		      "target": event.request.hostname,
		      "new": context,
		      "source": ip
		      };
	  
	  var embargo_response;
	  try{
		      //console.log("Checking Embargo IP : '%s'", ip);
		      embargo_response = await embargo.ipCheck(ip);
		      data.new['embargo_response'] = embargo_response.gotResponse.body;
		      //console.log("Response: ", ebmargo_response.gotResponse.body);
		    } catch(error){
			        embargo_response = {"status":"Failed", "summary":error};
			      };
	  
	  if (embargo_response.status == "Success" && embargo_response.result.count == 0){
		      data["status"] = "Success";
		      data["message"] = "Passed Embargo Check";
		    }
	  else{
		      // localize the error message 
		      const LOCALIZED_MESSAGES = {
			            en: 'Embargo Check Failed.',
			            es: 'No tienes permitido registrarte.'
			          };
		      const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
		      api.access.deny('embargo_check_failed', userMessage);
		      data["status"] = "Failed";
		      data["message"] = "Failed Embargo Check - " + embargo_response.summary;
		    };
	  //console.log("Data: ", data);
	  const logResponse = await audit.log(data);
	  //console.log("Data: ", logResponse)
	};
