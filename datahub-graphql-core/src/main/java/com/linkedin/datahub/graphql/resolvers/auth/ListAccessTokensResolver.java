package com.linkedin.datahub.graphql.resolvers.auth;

import com.google.common.collect.ImmutableSet;
import com.linkedin.datahub.graphql.QueryContext;
import com.linkedin.datahub.graphql.authorization.AuthorizationUtils;
import com.linkedin.datahub.graphql.exception.AuthorizationException;
import com.linkedin.datahub.graphql.generated.EntityType;
import com.linkedin.datahub.graphql.generated.FacetFilterInput;
import com.linkedin.datahub.graphql.generated.ListAccessTokenInput;
import com.linkedin.datahub.graphql.generated.ListAccessTokenResult;
import com.linkedin.datahub.graphql.generated.AccessTokenMetadata;
import com.linkedin.entity.client.EntityClient;
import com.linkedin.metadata.Constants;
import com.linkedin.metadata.query.filter.SortCriterion;
import com.linkedin.metadata.query.filter.SortOrder;
import com.linkedin.metadata.search.SearchResult;
import com.linkedin.metadata.search.utils.QueryUtils;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

import static com.linkedin.datahub.graphql.resolvers.ResolverUtils.*;


/**
 * Resolver for listing personal & service principal v2-type (stateful) access tokens.
 */
@Slf4j
public class ListAccessTokensResolver implements DataFetcher<CompletableFuture<ListAccessTokenResult>> {

  private static final String EXPIRES_AT_FIELD_NAME = "expiresAt";
  private static final Set<String> FACET_FIELDS =
      ImmutableSet.of("ownerUrn", "actorUrn", "name", "createdAt", "expiredAt", "description");

  private final EntityClient _entityClient;

  public ListAccessTokensResolver(final EntityClient entityClient) {
    this._entityClient = entityClient;
  }

  @Override
  public CompletableFuture<ListAccessTokenResult> get(DataFetchingEnvironment environment) throws Exception {
    return CompletableFuture.supplyAsync(() -> {
      final QueryContext context = environment.getContext();
      final ListAccessTokenInput input = bindArgument(environment.getArgument("input"), ListAccessTokenInput.class);
      final Integer start = input.getStart();
      final Integer count = input.getCount();
      final List<FacetFilterInput> filters = input.getFilters() == null ? Collections.emptyList() : input.getFilters();

      log.info("User {} listing access tokens with filters {}", context.getActorUrn(), filters.toString());

      if (AuthorizationUtils.canManageTokens(context) || isListingSelfTokens(filters, context)) {
        try {
          final SortCriterion sortCriterion =
              new SortCriterion().setField(EXPIRES_AT_FIELD_NAME).setOrder(SortOrder.DESCENDING);

          final SearchResult searchResult = _entityClient.search(Constants.ACCESS_TOKEN_ENTITY_NAME, "",
              QueryUtils.newFilter(buildFacetFilters(filters, FACET_FIELDS)), sortCriterion, start, count,
              getAuthentication(environment));

          final List<AccessTokenMetadata> tokens = searchResult.getEntities().stream().map(entity -> {
            final AccessTokenMetadata metadata = new AccessTokenMetadata();
            metadata.setUrn(entity.getEntity().toString());
            metadata.setType(EntityType.ACCESS_TOKEN);
            return metadata;
          }).collect(Collectors.toList());

          final ListAccessTokenResult result = new ListAccessTokenResult();
          result.setTokens(tokens);
          result.setStart(searchResult.getFrom());
          result.setCount(searchResult.getPageSize());
          result.setTotal(searchResult.getNumEntities());

          return result;
        } catch (Exception e) {
          throw new RuntimeException("Failed to list access tokens", e);
        }
      }
      throw new AuthorizationException(
          "Unauthorized to perform this action. Please contact your DataHub administrator.");
    });
  }

  /**
   * Utility method to answer: Does the existing security context have permissions to generate their personal tokens
   * AND is the request coming in requesting those personal tokens?
   * <p>
   * Note: We look for the actorUrn field because a token generated by someone else means that the generator actor has
   * manage all access token privileges which means that he/she will be bound to just listing their own tokens.
   *
   * @param filters The filters being used in the request.
   * @param context Current security context.
   * @return A boolean stating if the current user can list its personal tokens.
   */
  private boolean isListingSelfTokens(final List<FacetFilterInput> filters, final QueryContext context) {
    return AuthorizationUtils.canGeneratePersonalAccessToken(context) && filters.stream()
        .anyMatch(filter -> filter.getField().equals("ownerUrn") && filter.getValue().equals(context.getActorUrn()));
  }
}
