package com.teqmonic.springsecurityjwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RegistrationDTO(@JsonProperty("user_name") String userName, @JsonProperty("password") String password) {

}
