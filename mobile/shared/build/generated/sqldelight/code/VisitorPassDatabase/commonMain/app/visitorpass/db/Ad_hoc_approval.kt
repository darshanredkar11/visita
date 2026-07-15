package app.visitorpass.db

import kotlin.String

public data class Ad_hoc_approval(
  public val id: String,
  public val visitor_name: String,
  public val visitor_phone: String,
  public val unit_identifier: String,
  public val status: String,
  public val created_at: String,
)
