function onelfunc(element) {
  element.isMouseOver = false; 

  element.addEventListener('mouseenter', () => {
      element.isMouseOver = true;
  });

  element.addEventListener('mouseleave', () => {
      element.isMouseOver = false;
  });
}

function loginUser(userData) {
    localStorage.setItem("loggedInUser", JSON.stringify(userData));
    document.querySelector(".username").textContent = userData.username;
}

function logoutUser() {
    localStorage.removeItem("loggedInUser");
    window.location.reload(); 
}


document.addEventListener("DOMContentLoaded", () => {
  const pfpButton = document.querySelector(".profile-btn");
  const pfpSidebar = document.querySelector(".profile-sidebar");
  const usernameText = document.querySelector(".username"); 

  const savedUser = localStorage.getItem("loggedInUser");

  if (savedUser) {
    const user = JSON.parse(savedUser);
    usernameText.textContent = user.username;
    console.log("Welcome back,", user.username);
  } else {
    document.querySelector(".loggedOut").classList.remove("noshow")
    document.querySelector(".loggedIn").classList.add("noshow")
  }

  pfpButton.addEventListener("click", (event) => {
    if (savedUser) {
      pfpSidebar.classList.toggle("profile-sidebar-open");
    }
    else{
      pfpSidebar.classList.toggle("profile-sidebar-logged-out");
    }
  });

  onelfunc(pfpButton);
  onelfunc(pfpSidebar);

  document.addEventListener("click" , () => {
    if(!pfpSidebar.isMouseOver && !pfpButton.isMouseOver){
      if (savedUser) {
        if(pfpSidebar.classList.contains("profile-sidebar-open")){
          pfpSidebar.classList.remove("profile-sidebar-open");
        }
      }
      else{
        if(pfpSidebar.classList.contains("profile-sidebar-logged-out")){
          pfpSidebar.classList.remove("profile-sidebar-logged-out");
        }
      }
    }
  });
  
  document.querySelector(".pfp-sidebar-close-btn").addEventListener("click" , () =>{
    if(pfpSidebar.classList.contains("profile-sidebar-logged-out")){
      pfpSidebar.classList.remove("profile-sidebar-logged-out");
    }
  })
});

