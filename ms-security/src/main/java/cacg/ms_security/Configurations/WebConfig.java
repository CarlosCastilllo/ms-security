package cacg.ms_security.Configurations;

import cacg.ms_security.Interceptors.SecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {


    @Autowired
    private SecurityInterceptor securityInterceptor;
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    

    @Override
    public void addInterceptors(InterceptorRegistry registry) {


        registry.addInterceptor(securityInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/public/**");


    }
}