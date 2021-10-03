package com.security.springsecurityjwt.responses;

import com.security.springsecurityjwt.model.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Collection;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserInfo {
	private String username;
	private Object roles;

	
	
}
