package app.visitorpass.db

import kotlin.ByteArray
import kotlin.String

public data class Visitor_pass(
  public val id: String,
  public val pass_number: String,
  public val visitor_name: String,
  public val visitor_phone_enc: ByteArray?,
  public val valid_from: String,
  public val valid_until: String,
  public val status: String,
  public val qr_payload: String,
)
