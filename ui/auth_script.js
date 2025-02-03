
function handleQueries(){
	const params = new URLSearchParams(window.location.search);
	if (params.get("status") === "success"){
		const html = "<strong>Congratulations!</strong> "
			+ "You can login as "
			+ `<strong>${params.get('username')}</strong>`
		addToNotificationDiv(html, "success");
	} else if ( params.get("status") === "unknownfailure" ){
		const html = "<strong>Unfortunately there were some unexpeted error!</strong>"
			+ "<br>"
			+ "";
		addToNotificationDiv(html, "error")
	} else if ( params.get("status") === "failure" ){
		for ( let key of params.keys()){
			if ( key === "status" ) { continue }
			switch ( key ) {
				case "password":
					addToNotificationDiv(`<p><strong>Password</strong> has to be:</p>
						<ul>
						<li>at least 7 characters long</li>
						<li>at max 31 characters longlong</li>
						</ul>`, "error")
					break;
				case "email":
					addToNotificationDiv(`<p>This <strong>Email</strong> is already taken</p>`, "error")
					break
				case "username":
					addToNotificationDiv(`<p>This <strong>Username</strong> is already taken</p>`, "error")
					break
				default:
					addToNotificationDiv(`<p>There was some other issue, sorry!</p>`, 'error')
					break;
			}
		}

	}
}




async function setUserData(){
	const data = await fetchUserData();
	document.getElementById("user-info-container").innerText = JSON.stringify(data, null, "\t")
}

async function fetchUserData(){
	try{
		const resp = await fetch("/api/auth/me", {
			"method": "GET",
			"credentials": "include"
		});
		const respData = await resp.json();
		if ( resp.status !== 200 ){
			addToNotificationDiv(`Status of /api/auth/me was ${resp.status} instead of 200!`,"error")
		}
		return respData
	} catch (err) {
		window.alert(err)
	}

}

function addToNotificationDiv(innerHTML, notificationStatus,){
	// set notification div
		const notification_div = document.querySelector("#notification-div")
	const htmlToPut = `<div class="${notificationStatus}">${innerHTML}</div>`
	if (notification_div.innerHTML.includes(htmlToPut)){return}
	notification_div.innerHTML += htmlToPut;
}

