/**
 * Azure Static Web App for Mantissa Log Frontend
 *
 * Hosts the React web interface with Azure AD authentication
 */

# Static Web App for frontend
resource "azurerm_static_web_app" "frontend" {
  name                = "swa-mantissa-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.static_web_app_location # Static Web Apps have limited regions
  sku_tier            = var.static_web_app_sku
  sku_size            = var.static_web_app_sku

  tags = local.common_tags
}

# Custom domain configuration (optional)
resource "azurerm_static_web_app_custom_domain" "custom" {
  count             = var.custom_domain != "" ? 1 : 0
  static_web_app_id = azurerm_static_web_app.frontend.id
  domain_name       = var.custom_domain
  validation_type   = "cname-delegation"
}

# API backend routing configuration
# This connects the Static Web App to Azure Functions
resource "azurerm_static_web_app_function_app_registration" "api" {
  static_web_app_id = azurerm_static_web_app.frontend.id
  function_app_id   = azurerm_linux_function_app.llm_query.id
}

# Variables for Static Web App
variable "static_web_app_location" {
  description = "Location for Static Web App (limited availability)"
  type        = string
  default     = "centralus"
}

variable "static_web_app_sku" {
  description = "SKU for Static Web App (Free or Standard)"
  type        = string
  default     = "Free"
}

variable "custom_domain" {
  description = "Custom domain for the web app (optional)"
  type        = string
  default     = ""
}

# Output the Static Web App URL
output "static_web_app_url" {
  description = "URL of the Static Web App"
  value       = azurerm_static_web_app.frontend.default_host_name
}

output "static_web_app_api_key" {
  description = "API key for deployment (sensitive)"
  value       = azurerm_static_web_app.frontend.api_key
  sensitive   = true
}

# Static Web App configuration file (staticwebapp.config.json)
# This should be placed in the web/ directory
locals {
  static_web_app_config = {
    routes = [
      {
        route  = "/api/*"
        rewrite = "/api/*"
      },
      {
        route  = "/*"
        rewrite = "/index.html"
      }
    ]
    navigationFallback = {
      rewrite = "/index.html"
      exclude = ["/images/*.{png,jpg,gif}", "/css/*", "/js/*", "/api/*"]
    }
    responseOverrides = {
      "401" = {
        rewrite = "/index.html"
        statusCode = 200
      }
      "404" = {
        rewrite = "/index.html"
        statusCode = 200
      }
    }
    globalHeaders = {
      "X-Content-Type-Options"    = "nosniff"
      "X-Frame-Options"           = "DENY"
      "X-XSS-Protection"          = "1; mode=block"
      "Content-Security-Policy"   = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
      "Referrer-Policy"           = "strict-origin-when-cross-origin"
    }
    mimeTypes = {
      ".json" = "application/json"
      ".wasm" = "application/wasm"
    }
  }
}

# Create the config file in local filesystem for deployment reference
resource "local_file" "static_web_app_config" {
  content  = jsonencode(local.static_web_app_config_with_auth)
  filename = "${path.module}/../../../web/staticwebapp.config.json"
}

# Static Web App configuration with Azure AD authentication
locals {
  static_web_app_config_with_auth = merge(local.static_web_app_config, {
    auth = {
      identityProviders = {
        azureActiveDirectory = {
          enabled = var.enable_azure_ad_auth
          registration = {
            openIdIssuer                           = var.azure_ad_tenant_id != "" ? "https://login.microsoftonline.com/${var.azure_ad_tenant_id}/v2.0" : null
            clientIdSettingName                    = "AZURE_AD_CLIENT_ID"
            clientSecretSettingName                = "AZURE_AD_CLIENT_SECRET"
          }
          login = {
            loginParameters = ["scope=openid profile email"]
          }
        }
      }
      rolesSource = "/api/roles"
      login = {
        allowedExternalRedirectUrls = var.allowed_redirect_urls
      }
    }
    routes = concat(local.static_web_app_config.routes, [
      {
        route     = "/login"
        redirect  = "/.auth/login/aad"
      },
      {
        route     = "/logout"
        redirect  = "/.auth/logout"
      },
      {
        route        = "/api/*"
        allowedRoles = var.enable_azure_ad_auth ? ["authenticated"] : ["anonymous"]
      },
      {
        route        = "/admin/*"
        allowedRoles = ["admin"]
      }
    ])
  })
}

# Variables for Azure AD authentication
variable "enable_azure_ad_auth" {
  description = "Enable Azure AD authentication for the Static Web App"
  type        = bool
  default     = false
}

variable "azure_ad_tenant_id" {
  description = "Azure AD tenant ID for authentication"
  type        = string
  default     = ""
}

variable "azure_ad_client_id" {
  description = "Azure AD client ID for authentication"
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_ad_client_secret" {
  description = "Azure AD client secret for authentication"
  type        = string
  default     = ""
  sensitive   = true
}

variable "allowed_redirect_urls" {
  description = "Allowed external redirect URLs for authentication"
  type        = list(string)
  default     = []
}

# App settings for Azure AD (applied when auth is enabled)
resource "azurerm_static_web_app" "frontend_settings" {
  count               = var.enable_azure_ad_auth ? 1 : 0
  name                = azurerm_static_web_app.frontend.name
  resource_group_name = azurerm_resource_group.main.name
  location            = var.static_web_app_location
  sku_tier            = var.static_web_app_sku
  sku_size            = var.static_web_app_sku

  app_settings = {
    "AZURE_AD_CLIENT_ID"     = var.azure_ad_client_id
    "AZURE_AD_CLIENT_SECRET" = var.azure_ad_client_secret
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [app_settings]
  }
}
